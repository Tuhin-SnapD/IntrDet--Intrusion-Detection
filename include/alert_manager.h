#pragma once

#include "intrdet_types.h"
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <boost/asio.hpp>

namespace IntrDet {

/**
 * @brief Alert management and distribution system
 * 
 * This class provides comprehensive alert management capabilities:
 * - Alert scoring and severity calculation
 * - Multiple output formats (JSON, Protobuf)
 * - REST/gRPC API endpoints
 * - Alert persistence and archiving
 * - Rate limiting and deduplication
 * - Real-time dashboard integration
 */
class AlertManager {
public:
    // Alert output callback type
    using AlertOutputCallback = std::function<void(const Alert&)>;
    
    // Configuration structure
    struct Config {
        // Alert processing
        size_t max_alerts_per_second = 1000;
        size_t alert_queue_size = 10000;
        std::chrono::seconds alert_retention{86400}; // 24 hours
        bool enable_deduplication = true;
        
        // Output configuration
        bool enable_json_output = true;
        bool enable_protobuf_output = false;
        bool enable_rest_api = true;
        bool enable_grpc_api = false;
        std::string output_directory = "./alerts";
        
        // API configuration
        uint16_t rest_port = 8080;
        uint16_t grpc_port = 9090;
        std::string rest_bind_address = "0.0.0.0";
        std::string grpc_bind_address = "0.0.0.0";
        
        // Dashboard integration
        bool enable_websocket = true;
        uint16_t websocket_port = 8081;
        std::string websocket_bind_address = "0.0.0.0";
    };

    explicit AlertManager(const Config& config = Config{});
    ~AlertManager();

    // Disable copy
    AlertManager(const AlertManager&) = delete;
    AlertManager& operator=(const AlertManager&) = delete;

    // Allow move
    AlertManager(AlertManager&&) noexcept;
    AlertManager& operator=(AlertManager&&) noexcept;

    /**
     * @brief Start the alert manager
     */
    void start();

    /**
     * @brief Stop the alert manager
     */
    void stop();

    /**
     * @brief Submit an alert for processing
     * @param alert Alert to process
     */
    void submit_alert(Alert alert);

    /**
     * @brief Add alert output callback
     * @param callback Function to call for each alert
     */
    void add_output_callback(AlertOutputCallback callback);

    /**
     * @brief Get alert statistics
     */
    struct AlertStatistics {
        uint64_t total_alerts_received;
        uint64_t alerts_processed;
        uint64_t alerts_dropped;
        uint64_t alerts_deduplicated;
        double processing_rate_aps; // alerts per second
        std::chrono::steady_clock::time_point last_update;
        
        // Per-severity statistics
        std::array<uint64_t, 4> severity_counts; // LOW, MEDIUM, HIGH, CRITICAL
    };
    
    AlertStatistics get_statistics() const;

    /**
     * @brief Get recent alerts
     * @param count Number of alerts to retrieve
     * @return Vector of recent alerts
     */
    std::vector<Alert> get_recent_alerts(size_t count = 100) const;

    /**
     * @brief Clear all alerts
     */
    void clear_alerts();

    /**
     * @brief Update configuration
     * @param new_config New configuration
     */
    void update_config(const Config& new_config);

private:
    // Alert processing methods
    void process_alerts();
    void process_single_alert(Alert& alert);
    AlertSeverity calculate_severity(const Alert& alert) const;
    double calculate_risk_score(const Alert& alert) const;
    bool is_duplicate(const Alert& alert) const;
    
    // Output methods
    void output_json(const Alert& alert);
    void output_protobuf(const Alert& alert);
    void broadcast_websocket(const Alert& alert);
    
    // API server methods
    void start_rest_server();
    void start_grpc_server();
    void start_websocket_server();
    void handle_rest_request(const boost::asio::ip::tcp::endpoint& endpoint);
    void handle_websocket_connection(const boost::asio::ip::tcp::endpoint& endpoint);
    
    // Helper methods
    std::string alert_to_json(const Alert& alert) const;
    std::string alert_to_protobuf(const Alert& alert) const;
    void save_alert_to_file(const Alert& alert);
    void cleanup_old_alerts();
    
    // Configuration
    Config config_;
    
    // Alert storage
    mutable std::mutex alerts_mutex_;
    std::queue<Alert> alert_queue_;
    std::vector<Alert> recent_alerts_;
    std::unordered_set<std::string> alert_signatures_; // For deduplication
    
    // Output callbacks
    std::vector<AlertOutputCallback> output_callbacks_;
    
    // Threading
    std::thread processing_thread_;
    std::atomic<bool> running_;
    std::atomic<bool> should_stop_;
    
    // Boost.Asio for networking
    boost::asio::io_context io_context_;
    std::unique_ptr<boost::asio::io_context::work> work_guard_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> rest_acceptor_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> websocket_acceptor_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    AlertStatistics stats_;
    std::chrono::steady_clock::time_point last_cleanup_;
    
    // Performance counters
    std::atomic<uint64_t> alerts_received_{0};
    std::atomic<uint64_t> alerts_processed_{0};
    std::atomic<uint64_t> alerts_dropped_{0};
    std::atomic<uint64_t> alerts_deduplicated_{0};
    
    // Rate limiting
    std::chrono::steady_clock::time_point last_alert_time_;
    std::atomic<uint32_t> alerts_this_second_{0};
};

/**
 * @brief JSON alert formatter
 */
class AlertJsonFormatter {
public:
    /**
     * @brief Format alert as JSON
     * @param alert Alert to format
     * @return JSON string
     */
    static std::string format(const Alert& alert);
    
    /**
     * @brief Format multiple alerts as JSON array
     * @param alerts Vector of alerts
     * @return JSON array string
     */
    static std::string format_array(const std::vector<Alert>& alerts);
    
    /**
     * @brief Format alert statistics as JSON
     * @param stats Alert statistics
     * @return JSON string
     */
    static std::string format_statistics(const AlertManager::AlertStatistics& stats);

private:
    static std::string severity_to_string(AlertSeverity severity);
    static std::string type_to_string(AlertType type);
    static std::string timestamp_to_string(const std::chrono::steady_clock::time_point& timestamp);
};

} // namespace IntrDet

