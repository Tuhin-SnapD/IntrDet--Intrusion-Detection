#include "alert_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace IntrDet {

AlertManager::AlertManager(const Config& config)
    : config_(config)
    , running_(false)
    , should_stop_(false)
    , work_guard_(std::make_unique<boost::asio::io_context::work>(io_context_))
    , last_cleanup_(std::chrono::steady_clock::now())
{
    // Initialize statistics
    stats_.total_alerts_received = 0;
    stats_.alerts_processed = 0;
    stats_.alerts_dropped = 0;
    stats_.alerts_deduplicated = 0;
    stats_.processing_rate_aps = 0.0;
    stats_.last_update = std::chrono::steady_clock::now();
    stats_.severity_counts.fill(0);
}

AlertManager::~AlertManager() {
    stop();
}

AlertManager::AlertManager(AlertManager&& other) noexcept
    : config_(std::move(other.config_))
    , alert_queue_(std::move(other.alert_queue_))
    , recent_alerts_(std::move(other.recent_alerts_))
    , alert_signatures_(std::move(other.alert_signatures_))
    , output_callbacks_(std::move(other.output_callbacks_))
    , processing_thread_(std::move(other.processing_thread_))
    , running_(other.running_.load())
    , should_stop_(other.should_stop_.load())
    , io_context_(std::move(other.io_context_))
    , work_guard_(std::move(other.work_guard_))
    , rest_acceptor_(std::move(other.rest_acceptor_))
    , websocket_acceptor_(std::move(other.websocket_acceptor_))
    , stats_(std::move(other.stats_))
    , last_cleanup_(std::move(other.last_cleanup_))
{
    other.running_ = false;
    other.should_stop_ = false;
}

AlertManager& AlertManager::operator=(AlertManager&& other) noexcept {
    if (this != &other) {
        stop();
        
        config_ = std::move(other.config_);
        alert_queue_ = std::move(other.alert_queue_);
        recent_alerts_ = std::move(other.recent_alerts_);
        alert_signatures_ = std::move(other.alert_signatures_);
        output_callbacks_ = std::move(other.output_callbacks_);
        processing_thread_ = std::move(other.processing_thread_);
        running_ = other.running_.load();
        should_stop_ = other.should_stop_.load();
        io_context_ = std::move(other.io_context_);
        work_guard_ = std::move(other.work_guard_);
        rest_acceptor_ = std::move(other.rest_acceptor_);
        websocket_acceptor_ = std::move(other.websocket_acceptor_);
        stats_ = std::move(other.stats_);
        last_cleanup_ = std::move(other.last_cleanup_);
        
        other.running_ = false;
        other.should_stop_ = false;
    }
    return *this;
}

void AlertManager::start() {
    if (running_.load()) {
        return;
    }
    
    running_ = true;
    should_stop_ = false;
    
    // Start processing thread
    processing_thread_ = std::thread(&AlertManager::process_alerts, this);
    
    // Start API servers if enabled
    if (config_.enable_rest_api) {
        start_rest_server();
    }
    
    if (config_.enable_websocket) {
        start_websocket_server();
    }
    
    // Start Boost.Asio
    io_context_.run();
}

void AlertManager::stop() {
    if (!running_.load()) {
        return;
    }
    
    should_stop_ = true;
    running_ = false;
    
    // Stop Boost.Asio
    work_guard_.reset();
    io_context_.stop();
    
    // Wait for processing thread
    if (processing_thread_.joinable()) {
        processing_thread_.join();
    }
}

void AlertManager::submit_alert(Alert alert) {
    alerts_received_++;
    
    // Rate limiting
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_alert_time_).count();
    
    if (elapsed >= 1) {
        alerts_this_second_ = 0;
        last_alert_time_ = now;
    }
    
    if (alerts_this_second_ >= config_.max_alerts_per_second) {
        alerts_dropped_++;
        return;
    }
    
    alerts_this_second_++;
    
    // Deduplication
    if (config_.enable_deduplication && is_duplicate(alert)) {
        alerts_deduplicated_++;
        return;
    }
    
    // Add to queue
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (alert_queue_.size() < config_.alert_queue_size) {
            alert_queue_.push(std::move(alert));
        } else {
            alerts_dropped_++;
        }
    }
}

void AlertManager::add_output_callback(AlertOutputCallback callback) {
    output_callbacks_.push_back(std::move(callback));
}

AlertManager::AlertStatistics AlertManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    AlertStatistics result = stats_;
    result.total_alerts_received = alerts_received_.load();
    result.alerts_processed = alerts_processed_.load();
    result.alerts_dropped = alerts_dropped_.load();
    result.alerts_deduplicated = alerts_deduplicated_.load();
    
    // Calculate processing rate
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - result.last_update).count();
    if (elapsed > 0) {
        result.processing_rate_aps = static_cast<double>(result.alerts_processed) / elapsed;
    }
    
    return result;
}

std::vector<Alert> AlertManager::get_recent_alerts(size_t count) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    std::vector<Alert> result;
    result.reserve(std::min(count, recent_alerts_.size()));
    
    auto start = recent_alerts_.rbegin();
    auto end = recent_alerts_.rbegin() + std::min(count, recent_alerts_.size());
    
    for (auto it = start; it != end; ++it) {
        result.push_back(*it);
    }
    
    return result;
}

void AlertManager::clear_alerts() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    alert_queue_ = std::queue<Alert>();
    recent_alerts_.clear();
    alert_signatures_.clear();
}

void AlertManager::update_config(const Config& new_config) {
    config_ = new_config;
}

void AlertManager::process_alerts() {
    while (running_.load() && !should_stop_.load()) {
        Alert alert;
        bool has_alert = false;
        
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            if (!alert_queue_.empty()) {
                alert = std::move(alert_queue_.front());
                alert_queue_.pop();
                has_alert = true;
            }
        }
        
        if (has_alert) {
            process_single_alert(alert);
            alerts_processed_++;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Clean up old alerts periodically
        cleanup_old_alerts();
    }
}

void AlertManager::process_single_alert(Alert& alert) {
    // Calculate severity if not set
    if (alert.severity == AlertSeverity::LOW) {
        alert.severity = calculate_severity(alert);
    }
    
    // Add to recent alerts
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        recent_alerts_.push_back(alert);
        
        // Keep only recent alerts
        if (recent_alerts_.size() > 1000) {
            recent_alerts_.erase(recent_alerts_.begin());
        }
        
        // Update severity counts
        if (static_cast<size_t>(alert.severity) < stats_.severity_counts.size()) {
            stats_.severity_counts[static_cast<size_t>(alert.severity) - 1]++;
        }
    }
    
    // Output alert
    if (config_.enable_json_output) {
        output_json(alert);
    }
    
    if (config_.enable_protobuf_output) {
        output_protobuf(alert);
    }
    
    if (config_.enable_websocket) {
        broadcast_websocket(alert);
    }
    
    // Call output callbacks
    for (const auto& callback : output_callbacks_) {
        try {
            callback(alert);
        } catch (const std::exception& e) {
            std::cerr << "Error in alert callback: " << e.what() << std::endl;
        }
    }
    
    // Save to file
    save_alert_to_file(alert);
}

AlertSeverity AlertManager::calculate_severity(const Alert& alert) const {
    // Simple severity calculation based on alert type and confidence
    switch (alert.type) {
        case AlertType::SYN_FLOOD:
        case AlertType::ML_ANOMALY:
            return AlertSeverity::HIGH;
        case AlertType::PORT_SCAN:
        case AlertType::RATE_LIMIT_EXCEEDED:
            return AlertSeverity::MEDIUM;
        case AlertType::ANOMALOUS_TRAFFIC:
        case AlertType::SUSPICIOUS_PAYLOAD:
            return alert.confidence_score > 0.8 ? AlertSeverity::MEDIUM : AlertSeverity::LOW;
        default:
            return AlertSeverity::LOW;
    }
}

double AlertManager::calculate_risk_score(const Alert& alert) const {
    // Simple risk scoring based on severity and confidence
    double base_score = static_cast<double>(alert.severity) * 25.0; // 25, 50, 75, 100
    return base_score * alert.confidence_score;
}

bool AlertManager::is_duplicate(const Alert& alert) const {
    // Create a simple signature for deduplication
    std::ostringstream oss;
    oss << alert.type << "_" << alert.source_ip << "_" << alert.destination_ip 
        << "_" << alert.source_port << "_" << alert.destination_port;
    
    std::string signature = oss.str();
    return alert_signatures_.find(signature) != alert_signatures_.end();
}

void AlertManager::output_json(const Alert& alert) {
    std::string json = AlertJsonFormatter::format(alert);
    std::cout << "ALERT: " << json << std::endl;
}

void AlertManager::output_protobuf(const Alert& alert) {
    // Placeholder for protobuf output
    std::cout << "PROTOBUF ALERT: " << alert.description << std::endl;
}

void AlertManager::broadcast_websocket(const Alert& alert) {
    // Placeholder for WebSocket broadcast
    std::string json = AlertJsonFormatter::format(alert);
    // In a real implementation, this would send to all connected WebSocket clients
}

void AlertManager::start_rest_server() {
    try {
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::address::from_string(config_.rest_bind_address),
            config_.rest_port
        );
        
        rest_acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(io_context_, endpoint);
        std::cout << "REST API server started on " << config_.rest_bind_address 
                  << ":" << config_.rest_port << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to start REST server: " << e.what() << std::endl;
    }
}

void AlertManager::start_grpc_server() {
    // Placeholder for gRPC server
    std::cout << "gRPC server not implemented yet" << std::endl;
}

void AlertManager::start_websocket_server() {
    try {
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::address::from_string(config_.websocket_bind_address),
            config_.websocket_port
        );
        
        websocket_acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(io_context_, endpoint);
        std::cout << "WebSocket server started on " << config_.websocket_bind_address 
                  << ":" << config_.websocket_port << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to start WebSocket server: " << e.what() << std::endl;
    }
}

void AlertManager::handle_rest_request(const boost::asio::ip::tcp::endpoint& endpoint) {
    (void)endpoint; // Suppress unused parameter warning
    // Placeholder for REST request handling
}

void AlertManager::handle_websocket_connection(const boost::asio::ip::tcp::endpoint& endpoint) {
    (void)endpoint; // Suppress unused parameter warning
    // Placeholder for WebSocket connection handling
}

std::string AlertManager::alert_to_json(const Alert& alert) const {
    return AlertJsonFormatter::format(alert);
}

std::string AlertManager::alert_to_protobuf(const Alert& alert) const {
    (void)alert; // Suppress unused parameter warning
    // Placeholder for protobuf serialization
    return "protobuf_placeholder";
}

void AlertManager::save_alert_to_file(const Alert& alert) {
    // Create output directory if it doesn't exist
    // In a real implementation, you'd use filesystem library
    
    // Save alert to file (simplified)
    std::string filename = config_.output_directory + "/alert_" + 
                          std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                              alert.timestamp.time_since_epoch()).count()) + ".json";
    
    // In a real implementation, you'd write the JSON to the file
    // For now, just print to console
    std::cout << "Saving alert to: " << filename << std::endl;
}

void AlertManager::cleanup_old_alerts() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_);
    
    if (elapsed < std::chrono::seconds(300)) { // Clean up every 5 minutes
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Remove old alerts from recent_alerts_
        auto cutoff_time = now - config_.alert_retention;
        recent_alerts_.erase(
            std::remove_if(recent_alerts_.begin(), recent_alerts_.end(),
                          [cutoff_time](const Alert& alert) {
                              return alert.timestamp < cutoff_time;
                          }),
            recent_alerts_.end()
        );
        
        // Clear old signatures
        alert_signatures_.clear();
    }
    
    last_cleanup_ = now;
}

// AlertJsonFormatter implementation
std::string AlertJsonFormatter::format(const Alert& alert) {
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << timestamp_to_string(alert.timestamp) << "\","
        << "\"type\":\"" << type_to_string(alert.type) << "\","
        << "\"severity\":\"" << severity_to_string(alert.severity) << "\","
        << "\"description\":\"" << alert.description << "\","
        << "\"source_ip\":\"" << alert.source_ip << "\","
        << "\"destination_ip\":\"" << alert.destination_ip << "\","
        << "\"source_port\":" << alert.source_port << ","
        << "\"destination_port\":" << alert.destination_port << ","
        << "\"confidence_score\":" << std::fixed << std::setprecision(3) << alert.confidence_score
        << "}";
    return oss.str();
}

std::string AlertJsonFormatter::format_array(const std::vector<Alert>& alerts) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < alerts.size(); ++i) {
        if (i > 0) oss << ",";
        oss << format(alerts[i]);
    }
    oss << "]";
    return oss.str();
}

std::string AlertJsonFormatter::format_statistics(const AlertManager::AlertStatistics& stats) {
    std::ostringstream oss;
    oss << "{"
        << "\"total_alerts_received\":" << stats.total_alerts_received << ","
        << "\"alerts_processed\":" << stats.alerts_processed << ","
        << "\"alerts_dropped\":" << stats.alerts_dropped << ","
        << "\"alerts_deduplicated\":" << stats.alerts_deduplicated << ","
        << "\"processing_rate_aps\":" << std::fixed << std::setprecision(2) << stats.processing_rate_aps << ","
        << "\"severity_counts\":[";
    
    for (size_t i = 0; i < stats.severity_counts.size(); ++i) {
        if (i > 0) oss << ",";
        oss << stats.severity_counts[i];
    }
    
    oss << "]}";
    return oss.str();
}

std::string AlertJsonFormatter::severity_to_string(AlertSeverity severity) {
    switch (severity) {
        case AlertSeverity::LOW: return "LOW";
        case AlertSeverity::MEDIUM: return "MEDIUM";
        case AlertSeverity::HIGH: return "HIGH";
        case AlertSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string AlertJsonFormatter::type_to_string(AlertType type) {
    switch (type) {
        case AlertType::SYN_FLOOD: return "SYN_FLOOD";
        case AlertType::PORT_SCAN: return "PORT_SCAN";
        case AlertType::ANOMALOUS_TRAFFIC: return "ANOMALOUS_TRAFFIC";
        case AlertType::SUSPICIOUS_PAYLOAD: return "SUSPICIOUS_PAYLOAD";
        case AlertType::RATE_LIMIT_EXCEEDED: return "RATE_LIMIT_EXCEEDED";
        case AlertType::ML_ANOMALY: return "ML_ANOMALY";
        default: return "UNKNOWN";
    }
}

std::string AlertJsonFormatter::timestamp_to_string(const std::chrono::steady_clock::time_point& timestamp) {
    auto time_t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + (timestamp - std::chrono::steady_clock::now())
    );
    
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace IntrDet

