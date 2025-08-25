#include "packet_sniffer.h"
#include "packet_parser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace IntrDet {

PacketSniffer::PacketSniffer(const Config& config)
    : config_(config)
    , pcap_handle_(nullptr)
    , running_(false)
    , should_stop_(false)
    , write_index_(0)
    , read_index_(0)
    , work_guard_(std::make_unique<boost::asio::io_context::work>(io_context_))
{
    // Initialize ring buffer
    ring_buffer_.resize(config.ring_buffer_size);
    
    // Initialize libpcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_ = pcap_open_live(
        config_.interface_name.c_str(),
        config_.snap_length,
        config_.promiscuous ? 1 : 0,
        config_.timeout_ms,
        errbuf
    );
    
    if (!pcap_handle_) {
        throw std::runtime_error("Failed to open interface: " + std::string(errbuf));
    }
    
    // Set buffer size
    if (pcap_set_buffer_size(pcap_handle_, config_.buffer_size) < 0) {
        std::cerr << "Warning: Failed to set buffer size" << std::endl;
    }
    
    // Set immediate mode if requested
    if (config_.immediate) {
        if (pcap_set_immediate_mode(pcap_handle_, 1) < 0) {
            std::cerr << "Warning: Failed to set immediate mode" << std::endl;
        }
    }
    
    // Compile and set filter if provided
    if (!config_.filter_expression.empty()) {
        struct bpf_program filter_program;
        if (pcap_compile(pcap_handle_, &filter_program, config_.filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
            throw std::runtime_error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle_)));
        }
        
        if (pcap_setfilter(pcap_handle_, &filter_program) < 0) {
            pcap_freecode(&filter_program);
            throw std::runtime_error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle_)));
        }
        
        pcap_freecode(&filter_program);
    }
    
    // Initialize statistics
    stats_.packets_captured = 0;
    stats_.packets_dropped = 0;
    stats_.packets_if_dropped = 0;
    stats_.capture_rate_pps = 0.0;
    stats_.drop_rate_percent = 0.0;
    last_stats_update_ = std::chrono::steady_clock::now();
}

PacketSniffer::~PacketSniffer() {
    stop();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
    }
}

PacketSniffer::PacketSniffer(PacketSniffer&& other) noexcept
    : config_(std::move(other.config_))
    , pcap_handle_(other.pcap_handle_)
    , running_(other.running_.load())
    , should_stop_(other.should_stop_.load())
    , packet_callback_(std::move(other.packet_callback_))
    , stats_(std::move(other.stats_))
    , last_stats_update_(std::move(other.last_stats_update_))
    , ring_buffer_(std::move(other.ring_buffer_))
    , write_index_(other.write_index_.load())
    , read_index_(other.read_index_.load())
    , io_context_(std::move(other.io_context_))
    , work_guard_(std::move(other.work_guard_))
{
    other.pcap_handle_ = nullptr;
    other.running_ = false;
    other.should_stop_ = false;
}

PacketSniffer& PacketSniffer::operator=(PacketSniffer&& other) noexcept {
    if (this != &other) {
        stop();
        if (pcap_handle_) {
            pcap_close(pcap_handle_);
        }
        
        config_ = std::move(other.config_);
        pcap_handle_ = other.pcap_handle_;
        running_ = other.running_.load();
        should_stop_ = other.should_stop_.load();
        packet_callback_ = std::move(other.packet_callback_);
        stats_ = std::move(other.stats_);
        last_stats_update_ = std::move(other.last_stats_update_);
        ring_buffer_ = std::move(other.ring_buffer_);
        write_index_ = other.write_index_.load();
        read_index_ = other.read_index_.load();
        io_context_ = std::move(other.io_context_);
        work_guard_ = std::move(other.work_guard_);
        
        other.pcap_handle_ = nullptr;
        other.running_ = false;
        other.should_stop_ = false;
    }
    return *this;
}

bool PacketSniffer::start(PacketCallback callback) {
    if (running_.load()) {
        return false;
    }
    
    packet_callback_ = std::move(callback);
    running_ = true;
    should_stop_ = false;
    
    // Start capture thread
    capture_thread_ = std::thread(&PacketSniffer::capture_loop, this);
    
    return true;
}

void PacketSniffer::stop() {
    if (!running_.load()) {
        return;
    }
    
    should_stop_ = true;
    running_ = false;
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    // Stop Boost.Asio
    work_guard_.reset();
    io_context_.stop();
}

void PacketSniffer::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* sniffer = reinterpret_cast<PacketSniffer*>(user);
    sniffer->process_packet(header, packet);
}

void PacketSniffer::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    // Create packet metadata
    PacketMetadata metadata;
    metadata.timestamp = std::chrono::steady_clock::now();
    metadata.length = header->len;
    metadata.captured_length = header->caplen;
    metadata.interface_index = 0; // TODO: Get from pcap
    metadata.interface_name = config_.interface_name;
    
    // Parse packet
    auto parsed_packet = PacketParser::parse_packet(packet, header->caplen, metadata);
    if (!parsed_packet) {
        return; // Skip invalid packets
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_captured++;
    }
    
    // Call callback if set
    if (packet_callback_) {
        packet_callback_(*parsed_packet);
    }
}

void PacketSniffer::capture_loop() {
    // Set packet handler
    pcap_handler handler = packet_handler;
    
    // Start capture loop
    while (running_.load() && !should_stop_.load()) {
        int result = pcap_dispatch(pcap_handle_, -1, handler, reinterpret_cast<u_char*>(this));
        
        if (result < 0) {
            if (result == PCAP_ERROR) {
                std::cerr << "pcap_dispatch error: " << pcap_geterr(pcap_handle_) << std::endl;
            }
            break;
        }
        
        // Update statistics periodically
        update_statistics();
    }
}

void PacketSniffer::update_statistics() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_update_).count();
    
    if (elapsed >= 1) { // Update every second
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        // Get pcap statistics
        struct pcap_stat pcap_stats;
        if (pcap_stats(pcap_handle_, &pcap_stats) == 0) {
            stats_.packets_dropped = pcap_stats.ps_drop;
            stats_.packets_if_dropped = pcap_stats.ps_ifdrop;
        }
        
        // Calculate rates
        if (elapsed > 0) {
            stats_.capture_rate_pps = static_cast<double>(stats_.packets_captured) / elapsed;
            uint64_t total_packets = stats_.packets_captured + stats_.packets_dropped;
            if (total_packets > 0) {
                stats_.drop_rate_percent = (static_cast<double>(stats_.packets_dropped) / total_packets) * 100.0;
            }
        }
        
        last_stats_update_ = now;
    }
}

PacketSniffer::Statistics PacketSniffer::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<std::string> PacketSniffer::list_interfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name) {
            interfaces.push_back(dev->name);
        }
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

std::string PacketSniffer::get_interface_description(const std::string& interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return "Error finding devices: " + std::string(errbuf);
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name && interface_name == dev->name) {
            std::string description = "Interface: " + std::string(dev->name);
            if (dev->description) {
                description += " (" + std::string(dev->description) + ")";
            }
            pcap_freealldevs(alldevs);
            return description;
        }
    }
    
    pcap_freealldevs(alldevs);
    return "Interface not found: " + interface_name;
}

} // namespace IntrDet

