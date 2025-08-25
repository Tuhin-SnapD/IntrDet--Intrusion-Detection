#pragma once

#include "intrdet_types.h"
#include <pcap.h>
#include <string>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <boost/asio.hpp>

namespace IntrDet {

/**
 * @brief High-performance packet sniffer using libpcap
 * 
 * This class provides asynchronous packet capture capabilities with:
 * - Zero-copy packet processing where possible
 * - Configurable capture filters
 * - Ring buffer for high-throughput scenarios
 * - Thread-safe packet callback mechanism
 */
class PacketSniffer {
public:
    // Callback type for packet processing
    using PacketCallback = std::function<void(const ParsedPacket&)>;
    
    // Configuration structure
    struct Config {
        std::string interface_name;
        std::string filter_expression;
        int snap_length = MAX_PACKET_SIZE;
        int timeout_ms = 1000;
        bool promiscuous = true;
        bool immediate = true;
        int buffer_size = 64 * 1024 * 1024; // 64MB buffer
        int ring_buffer_size = 1024 * 1024;  // 1MB ring buffer
    };

    explicit PacketSniffer(const Config& config);
    ~PacketSniffer();

    // Disable copy
    PacketSniffer(const PacketSniffer&) = delete;
    PacketSniffer& operator=(const PacketSniffer&) = delete;

    // Allow move
    PacketSniffer(PacketSniffer&&) noexcept;
    PacketSniffer& operator=(PacketSniffer&&) noexcept;

    /**
     * @brief Start packet capture
     * @param callback Function to call for each captured packet
     * @return true if capture started successfully
     */
    bool start(PacketCallback callback);

    /**
     * @brief Stop packet capture
     */
    void stop();

    /**
     * @brief Check if capture is running
     */
    bool is_running() const { return running_.load(); }

    /**
     * @brief Get capture statistics
     */
    struct Statistics {
        uint64_t packets_captured;
        uint64_t packets_dropped;
        uint64_t packets_if_dropped;
        double capture_rate_pps;
        double drop_rate_percent;
    };
    
    Statistics get_statistics() const;

    /**
     * @brief List available network interfaces
     */
    static std::vector<std::string> list_interfaces();

    /**
     * @brief Get interface details
     */
    static std::string get_interface_description(const std::string& interface_name);

private:
    // Internal packet buffer for zero-copy processing
    struct PacketBuffer {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point timestamp;
        uint32_t length;
        uint32_t captured_length;
    };

    // libpcap callback function
    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

    // Internal processing methods
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    void capture_loop();
    void update_statistics();

    // Configuration
    Config config_;
    
    // libpcap handle
    pcap_t* pcap_handle_;
    
    // Threading
    std::thread capture_thread_;
    std::atomic<bool> running_;
    std::atomic<bool> should_stop_;
    
    // Callback
    PacketCallback packet_callback_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Statistics stats_;
    std::chrono::steady_clock::time_point last_stats_update_;
    
    // Ring buffer for high-throughput scenarios
    std::vector<PacketBuffer> ring_buffer_;
    std::atomic<size_t> write_index_;
    std::atomic<size_t> read_index_;
    
    // Boost.Asio for async processing
    boost::asio::io_context io_context_;
    std::unique_ptr<boost::asio::io_context::work> work_guard_;
};

} // namespace IntrDet

