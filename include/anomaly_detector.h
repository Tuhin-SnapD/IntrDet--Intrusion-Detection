#pragma once

#include "intrdet_types.h"
#include <unordered_map>
#include <deque>
#include <memory>
#include <functional>
#include <chrono>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <cmath>
#include <vector>
#include <string>

#ifdef ENABLE_ML_INFERENCE
#include <onnxruntime_cxx_api.h>
#endif

namespace IntrDet {

/**
 * @brief Anomaly detection engine with rule-based and ML-based detection
 * 
 * This class provides comprehensive anomaly detection capabilities:
 * - Rule-based detection (SYN flood, port scans, etc.)
 * - Statistical anomaly detection (z-score, moving averages)
 * - ML-based inference using ONNX Runtime
 * - Configurable thresholds and rules
 * - Real-time scoring and alerting
 */
class AnomalyDetector {
public:
    // Alert callback type
    using AlertCallback = std::function<void(const Alert&)>;
    
    // Configuration structure
    struct Config {
        // Rule-based detection thresholds
        uint32_t syn_flood_threshold;
        uint32_t port_scan_threshold;
        uint32_t connection_rate_threshold;
        uint32_t payload_size_threshold;
        
        // Statistical detection parameters
        double z_score_threshold;
        size_t moving_average_window;
        double anomaly_confidence_threshold;
        
        // Time windows
        std::chrono::seconds syn_flood_window;
        std::chrono::seconds port_scan_window;
        std::chrono::seconds connection_window;
        std::chrono::seconds statistics_window;
        
        // ML model configuration
        std::string ml_model_path;
        bool enable_ml_inference;
        
        Config() 
            : syn_flood_threshold(100)
            , port_scan_threshold(50)
            , connection_rate_threshold(1000)
            , payload_size_threshold(1500)
            , z_score_threshold(3.0)
            , moving_average_window(1000)
            , anomaly_confidence_threshold(0.8)
            , syn_flood_window(1)
            , port_scan_window(60)
            , connection_window(1)
            , statistics_window(300)
            , ml_model_path("")
            , enable_ml_inference(false) {}
    };

    explicit AnomalyDetector(const Config& config = Config{});
    ~AnomalyDetector();

    // Disable copy
    AnomalyDetector(const AnomalyDetector&) = delete;
    AnomalyDetector& operator=(const AnomalyDetector&) = delete;

    // Allow move
    AnomalyDetector(AnomalyDetector&&) noexcept;
    AnomalyDetector& operator=(AnomalyDetector&&) noexcept;

    /**
     * @brief Set alert callback
     * @param callback Function to call when anomalies are detected
     */
    void set_alert_callback(AlertCallback callback);

    /**
     * @brief Process a packet for anomaly detection
     * @param packet Packet to analyze
     */
    void process_packet(const ParsedPacket& packet);

    /**
     * @brief Get current detection statistics
     */
    struct DetectionStatistics {
        uint64_t total_packets_analyzed;
        uint64_t anomalies_detected;
        uint64_t rule_based_alerts;
        uint64_t statistical_alerts;
        uint64_t ml_alerts;
        double detection_rate;
        std::chrono::steady_clock::time_point last_update;
    };
    
    DetectionStatistics get_statistics() const;

    /**
     * @brief Update configuration
     * @param new_config New configuration
     */
    void update_config(const Config& new_config);

    /**
     * @brief Load ML model
     * @param model_path Path to ONNX model file
     * @return true if model loaded successfully
     */
    bool load_ml_model(const std::string& model_path);

private:
    // Rule-based detection methods
    void detect_syn_flood(const ParsedPacket& packet);
    void detect_port_scan(const ParsedPacket& packet);
    void detect_connection_flood(const ParsedPacket& packet);
    void detect_suspicious_payload(const ParsedPacket& packet);
    
    // Statistical detection methods
    void update_statistical_models(const ParsedPacket& packet);
    void detect_statistical_anomalies(const ParsedPacket& packet);
    double calculate_z_score(double value, double mean, double std_dev) const;
    
    // ML-based detection methods
    void detect_ml_anomalies(const ParsedPacket& packet);
    std::vector<float> extract_features(const ParsedPacket& packet) const;
    
    // Helper methods
    void create_alert(AlertType type, AlertSeverity severity, 
                     const std::string& description, const ParsedPacket& packet,
                     double confidence = 1.0);
    void cleanup_old_entries();
    void update_detection_statistics();
    std::string ip_to_string(const IpAddress& ip) const;
    
    // Configuration
    Config config_;
    
    // Alert callback
    AlertCallback alert_callback_;
    
    // Rule-based detection state
    struct ConnectionTracker {
        std::chrono::steady_clock::time_point first_seen;
        uint32_t syn_count;
        uint32_t connection_count;
    };
    
    struct PortScanTracker {
        std::chrono::steady_clock::time_point first_seen;
        std::unordered_set<uint16_t> ports;
        std::string source_ip;
    };
    
    // Tracking maps
    std::unordered_map<std::string, ConnectionTracker> connection_trackers_;
    std::unordered_map<std::string, PortScanTracker> port_scan_trackers_;
    
    // Statistical models
    struct StatisticalModel {
        std::deque<double> values;
        double sum;
        double sum_squares;
        size_t count;
        
        void add_value(double value) {
            values.push_back(value);
            sum += value;
            sum_squares += value * value;
            count++;
            
            if (values.size() > 1000) { // Keep last 1000 values
                sum -= values.front();
                sum_squares -= values.front() * values.front();
                values.pop_front();
                count--;
            }
        }
        
        double mean() const { return count > 0 ? sum / count : 0.0; }
        double variance() const { 
            if (count <= 1) return 0.0;
            double m = mean();
            return (sum_squares / count) - (m * m);
        }
        double std_dev() const { return std::sqrt(variance()); }
    };
    
    std::unordered_map<std::string, StatisticalModel> packet_size_models_;
    std::unordered_map<std::string, StatisticalModel> packet_rate_models_;
    
    // ML inference
#ifdef ENABLE_ML_INFERENCE
    std::unique_ptr<Ort::Env> onnx_env_;
    std::unique_ptr<Ort::Session> onnx_session_;
    std::vector<const char*> input_names_;
    std::vector<const char*> output_names_;
    bool ml_model_loaded_;
#endif
    
    // Statistics
    mutable std::mutex stats_mutex_;
    DetectionStatistics stats_;
    std::chrono::steady_clock::time_point last_cleanup_;
    
    // Performance counters
    std::atomic<uint64_t> packets_analyzed_{0};
    std::atomic<uint64_t> anomalies_detected_{0};
    std::atomic<uint64_t> rule_based_alerts_{0};
    std::atomic<uint64_t> statistical_alerts_{0};
    std::atomic<uint64_t> ml_alerts_{0};
};

} // namespace IntrDet

