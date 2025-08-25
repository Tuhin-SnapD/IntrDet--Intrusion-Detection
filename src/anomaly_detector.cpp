#include "anomaly_detector.h"
#include "packet_parser.h"
#include <iostream>
#include <cmath>
#include <mutex>

namespace IntrDet {

AnomalyDetector::AnomalyDetector(const Config& config)
    : config_(config)
    , last_cleanup_(std::chrono::steady_clock::now())
#ifdef ENABLE_ML_INFERENCE
    , ml_model_loaded_(false)
#endif
{
    // Initialize statistics
    stats_.total_packets_analyzed = 0;
    stats_.anomalies_detected = 0;
    stats_.rule_based_alerts = 0;
    stats_.statistical_alerts = 0;
    stats_.ml_alerts = 0;
    stats_.detection_rate = 0.0;
    stats_.last_update = std::chrono::steady_clock::now();
}

AnomalyDetector::~AnomalyDetector() = default;

AnomalyDetector::AnomalyDetector(AnomalyDetector&& other) noexcept
    : config_(std::move(other.config_))
    , alert_callback_(std::move(other.alert_callback_))
    , connection_trackers_(std::move(other.connection_trackers_))
    , port_scan_trackers_(std::move(other.port_scan_trackers_))
    , packet_size_models_(std::move(other.packet_size_models_))
    , packet_rate_models_(std::move(other.packet_rate_models_))
    , stats_(std::move(other.stats_))
    , last_cleanup_(std::move(other.last_cleanup_))
#ifdef ENABLE_ML_INFERENCE
    , onnx_env_(std::move(other.onnx_env_))
    , onnx_session_(std::move(other.onnx_session_))
    , input_names_(std::move(other.input_names_))
    , output_names_(std::move(other.output_names_))
    , ml_model_loaded_(other.ml_model_loaded_)
#endif
{
}

AnomalyDetector& AnomalyDetector::operator=(AnomalyDetector&& other) noexcept {
    if (this != &other) {
        config_ = std::move(other.config_);
        alert_callback_ = std::move(other.alert_callback_);
        connection_trackers_ = std::move(other.connection_trackers_);
        port_scan_trackers_ = std::move(other.port_scan_trackers_);
        packet_size_models_ = std::move(other.packet_size_models_);
        packet_rate_models_ = std::move(other.packet_rate_models_);
        stats_ = std::move(other.stats_);
        last_cleanup_ = std::move(other.last_cleanup_);
#ifdef ENABLE_ML_INFERENCE
        onnx_env_ = std::move(other.onnx_env_);
        onnx_session_ = std::move(other.onnx_session_);
        input_names_ = std::move(other.input_names_);
        output_names_ = std::move(other.output_names_);
        ml_model_loaded_ = other.ml_model_loaded_;
#endif
    }
    return *this;
}

void AnomalyDetector::set_alert_callback(AlertCallback callback) {
    alert_callback_ = std::move(callback);
}

void AnomalyDetector::process_packet(const ParsedPacket& packet) {
    packets_analyzed_++;
    
    // Clean up old entries periodically
    cleanup_old_entries();
    
    // Rule-based detection
    detect_syn_flood(packet);
    detect_port_scan(packet);
    detect_connection_flood(packet);
    detect_suspicious_payload(packet);
    
    // Statistical detection
    update_statistical_models(packet);
    detect_statistical_anomalies(packet);
    
    // ML-based detection
    if (config_.enable_ml_inference) {
        detect_ml_anomalies(packet);
    }
    
    // Update statistics
    update_detection_statistics();
}

AnomalyDetector::DetectionStatistics AnomalyDetector::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    DetectionStatistics result = stats_;
    result.total_packets_analyzed = packets_analyzed_.load();
    result.anomalies_detected = anomalies_detected_.load();
    result.rule_based_alerts = rule_based_alerts_.load();
    result.statistical_alerts = statistical_alerts_.load();
    result.ml_alerts = ml_alerts_.load();
    
    if (result.total_packets_analyzed > 0) {
        result.detection_rate = static_cast<double>(result.anomalies_detected) / result.total_packets_analyzed;
    }
    
    return result;
}

void AnomalyDetector::update_config(const Config& new_config) {
    config_ = new_config;
}

bool AnomalyDetector::load_ml_model(const std::string& model_path) {
#ifdef ENABLE_ML_INFERENCE
    try {
        // Initialize ONNX Runtime environment
        onnx_env_ = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "IntrDet");
        
        // Create session options
        Ort::SessionOptions session_options;
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
        
        // Load the model
        onnx_session_ = std::make_unique<Ort::Session>(*onnx_env_, model_path.c_str(), session_options);
        
        // Get input and output names
        Ort::AllocatorWithDefaultOptions allocator;
        input_names_.clear();
        output_names_.clear();
        
        for (size_t i = 0; i < onnx_session_->GetInputCount(); ++i) {
            input_names_.push_back(onnx_session_->GetInputName(i, allocator));
        }
        
        for (size_t i = 0; i < onnx_session_->GetOutputCount(); ++i) {
            output_names_.push_back(onnx_session_->GetOutputName(i, allocator));
        }
        
        ml_model_loaded_ = true;
        return true;
        
    } catch (const Ort::Exception& e) {
        std::cerr << "Failed to load ML model: " << e.what() << std::endl;
        ml_model_loaded_ = false;
        return false;
    }
#else
    std::cerr << "ML inference not enabled" << std::endl;
    return false;
#endif
}

void AnomalyDetector::detect_syn_flood(const ParsedPacket& packet) {
    if (!packet.is_tcp()) {
        return;
    }
    
    // Check if this is a SYN packet
    if (!(packet.transport.tcp.flags() & TcpHeader::SYN)) {
        return;
    }
    
    std::string source_ip = ip_to_string(packet.ip.source);
    auto now = std::chrono::steady_clock::now();
    
    // Get or create connection tracker
    auto& tracker = connection_trackers_[source_ip];
    if (tracker.syn_count == 0) {
        tracker.first_seen = now;
    }
    
    tracker.syn_count++;
    
    // Check if we've exceeded the threshold
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.first_seen);
    if (elapsed <= config_.syn_flood_window && tracker.syn_count >= config_.syn_flood_threshold) {
        create_alert(AlertType::SYN_FLOOD, AlertSeverity::HIGH,
                    "SYN flood detected from " + source_ip, packet);
        rule_based_alerts_++;
    }
}

void AnomalyDetector::detect_port_scan(const ParsedPacket& packet) {
    if (!packet.is_tcp() && !packet.is_udp()) {
        return;
    }
    
    std::string source_ip = ip_to_string(packet.ip.source);
    auto now = std::chrono::steady_clock::now();
    
    // Get or create port scan tracker
    auto& tracker = port_scan_trackers_[source_ip];
    if (tracker.ports.empty()) {
        tracker.first_seen = now;
        tracker.source_ip = source_ip;
    }
    
    tracker.ports.insert(packet.destination_port());
    
    // Check if we've exceeded the threshold
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.first_seen);
    if (elapsed <= config_.port_scan_window && tracker.ports.size() >= config_.port_scan_threshold) {
        create_alert(AlertType::PORT_SCAN, AlertSeverity::MEDIUM,
                    "Port scan detected from " + source_ip + " (" + 
                    std::to_string(tracker.ports.size()) + " ports)", packet);
        rule_based_alerts_++;
    }
}

void AnomalyDetector::detect_connection_flood(const ParsedPacket& packet) {
    if (!packet.is_tcp()) {
        return;
    }
    
    std::string source_ip = ip_to_string(packet.ip.source);
    auto now = std::chrono::steady_clock::now();
    
    // Get or create connection tracker
    auto& tracker = connection_trackers_[source_ip];
    if (tracker.connection_count == 0) {
        tracker.first_seen = now;
    }
    
    tracker.connection_count++;
    
    // Check if we've exceeded the threshold
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.first_seen);
    if (elapsed <= config_.connection_window && tracker.connection_count >= config_.connection_rate_threshold) {
        create_alert(AlertType::RATE_LIMIT_EXCEEDED, AlertSeverity::HIGH,
                    "Connection flood detected from " + source_ip, packet);
        rule_based_alerts_++;
    }
}

void AnomalyDetector::detect_suspicious_payload(const ParsedPacket& packet) {
    if (packet.payload_length > config_.payload_size_threshold) {
        std::string source_ip = ip_to_string(packet.ip.source);
        create_alert(AlertType::SUSPICIOUS_PAYLOAD, AlertSeverity::MEDIUM,
                    "Large payload detected from " + source_ip + 
                    " (" + std::to_string(packet.payload_length) + " bytes)", packet);
        rule_based_alerts_++;
    }
}

void AnomalyDetector::update_statistical_models(const ParsedPacket& packet) {
    std::string source_ip = ip_to_string(packet.ip.source);
    
    // Update packet size model
    packet_size_models_[source_ip].add_value(static_cast<double>(packet.metadata.length));
    
    // Update packet rate model (simplified - just count packets per second)
    auto now = std::chrono::steady_clock::now();
    static auto last_rate_update = now;
    static uint32_t packet_count = 0;
    
    packet_count++;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_rate_update);
    if (elapsed.count() >= 1) {
        packet_rate_models_[source_ip].add_value(static_cast<double>(packet_count));
        packet_count = 0;
        last_rate_update = now;
    }
}

void AnomalyDetector::detect_statistical_anomalies(const ParsedPacket& packet) {
    std::string source_ip = ip_to_string(packet.ip.source);
    
    // Check packet size anomalies
    auto& size_model = packet_size_models_[source_ip];
    if (size_model.count > 10) { // Need enough samples
        double z_score = calculate_z_score(static_cast<double>(packet.metadata.length),
                                         size_model.mean(), size_model.std_dev());
        if (std::abs(z_score) > config_.z_score_threshold) {
            create_alert(AlertType::ANOMALOUS_TRAFFIC, AlertSeverity::MEDIUM,
                        "Anomalous packet size from " + source_ip + 
                        " (z-score: " + std::to_string(z_score) + ")", packet);
            statistical_alerts_++;
        }
    }
}

double AnomalyDetector::calculate_z_score(double value, double mean, double std_dev) const {
    if (std_dev == 0.0) {
        return 0.0;
    }
    return (value - mean) / std_dev;
}

void AnomalyDetector::detect_ml_anomalies(const ParsedPacket& packet) {
#ifdef ENABLE_ML_INFERENCE
    if (!ml_model_loaded_) {
        return;
    }
    
    try {
        // Extract features
        auto features = extract_features(packet);
        
        // Prepare input tensor
        std::vector<float> input_tensor_values = features;
        std::vector<int64_t> input_shape = {1, static_cast<int64_t>(features.size())};
        
        auto memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            memory_info, input_tensor_values.data(), input_tensor_values.size(),
            input_shape.data(), input_shape.size());
        
        // Run inference
        auto output_tensors = onnx_session_->Run(
            Ort::RunOptions{nullptr}, input_names_.data(), &input_tensor, 1,
            output_names_.data(), output_names_.size());
        
        // Get prediction
        float* output_data = output_tensors[0].GetTensorMutableData<float>();
        double confidence = static_cast<double>(output_data[0]);
        
        if (confidence > config_.anomaly_confidence_threshold) {
            std::string source_ip = ip_to_string(packet.ip.source);
            create_alert(AlertType::ML_ANOMALY, AlertSeverity::HIGH,
                        "ML anomaly detected from " + source_ip + 
                        " (confidence: " + std::to_string(confidence) + ")", packet, confidence);
            ml_alerts_++;
        }
        
    } catch (const Ort::Exception& e) {
        std::cerr << "ML inference error: " << e.what() << std::endl;
    }
#endif
}

std::vector<float> AnomalyDetector::extract_features(const ParsedPacket& packet) const {
    // Simple feature extraction - in a real implementation, this would be more sophisticated
    std::vector<float> features;
    
    // Basic packet features
    features.push_back(static_cast<float>(packet.metadata.length));
    features.push_back(static_cast<float>(packet.payload_length));
    features.push_back(static_cast<float>(packet.ip.ttl));
    features.push_back(static_cast<float>(packet.ip.protocol));
    
    // Port features
    features.push_back(static_cast<float>(packet.source_port()));
    features.push_back(static_cast<float>(packet.destination_port()));
    
    // TCP flags (if applicable)
    if (packet.is_tcp()) {
        features.push_back(static_cast<float>(packet.transport.tcp.flags()));
        features.push_back(static_cast<float>(packet.transport.tcp.window_size));
    } else {
        features.push_back(0.0f);
        features.push_back(0.0f);
    }
    
    // Normalize features (simple min-max normalization)
    // In a real implementation, you'd use proper normalization
    for (auto& feature : features) {
        feature = std::min(1.0f, std::max(0.0f, feature / 65535.0f));
    }
    
    return features;
}

void AnomalyDetector::create_alert(AlertType type, AlertSeverity severity,
                                  const std::string& description, const ParsedPacket& packet,
                                  double confidence) {
    Alert alert;
    alert.timestamp = std::chrono::steady_clock::now();
    alert.type = type;
    alert.severity = severity;
    alert.description = description;
    alert.source_ip = ip_to_string(packet.ip.source);
    alert.destination_ip = ip_to_string(packet.ip.destination);
    alert.source_port = packet.source_port();
    alert.destination_port = packet.destination_port();
    alert.confidence_score = confidence;
    
    anomalies_detected_++;
    
    if (alert_callback_) {
        alert_callback_(alert);
    }
}

void AnomalyDetector::cleanup_old_entries() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_);
    
    if (elapsed < std::chrono::seconds(60)) { // Clean up every minute
        return;
    }
    
    // Clean up old connection trackers
    for (auto it = connection_trackers_.begin(); it != connection_trackers_.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_seen);
        if (age > config_.statistics_window) {
            it = connection_trackers_.erase(it);
        } else {
            ++it;
        }
    }
    
    // Clean up old port scan trackers
    for (auto it = port_scan_trackers_.begin(); it != port_scan_trackers_.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_seen);
        if (age > config_.port_scan_window) {
            it = port_scan_trackers_.erase(it);
        } else {
            ++it;
        }
    }
    
    last_cleanup_ = now;
}

std::string AnomalyDetector::ip_to_string(const IpAddress& ip) const {
    return PacketParser::ip_to_string(ip);
}

void AnomalyDetector::update_detection_statistics() {
    // Update statistics periodically
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.last_update);
    
    if (elapsed >= std::chrono::seconds(60)) { // Update every minute
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_packets_analyzed = packets_analyzed_.load();
        stats_.anomalies_detected = anomalies_detected_.load();
        stats_.rule_based_alerts = rule_based_alerts_.load();
        stats_.statistical_alerts = statistical_alerts_.load();
        stats_.ml_alerts = ml_alerts_.load();
        
        if (stats_.total_packets_analyzed > 0) {
            stats_.detection_rate = static_cast<double>(stats_.anomalies_detected) / stats_.total_packets_analyzed;
        }
        
        stats_.last_update = now;
    }
}

} // namespace IntrDet

