#include "packet_sniffer.h"
#include "packet_parser.h"
#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>

using namespace IntrDet;

// Global flag for graceful shutdown
std::atomic<bool> g_running(true);

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}

// Packet callback function
void packet_callback(const ParsedPacket& packet) {
    // Print basic packet information
    std::cout << "Packet: ";
    
    // Print timestamp
    auto time_point = packet.metadata.timestamp;
    auto time_t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() + (time_point - std::chrono::steady_clock::now())
    );
    std::cout << std::ctime(&time_t);
    
    // Print Ethernet information
    std::cout << "  Ethernet: " 
              << PacketParser::mac_to_string(packet.ethernet.source) << " -> "
              << PacketParser::mac_to_string(packet.ethernet.destination);
    
    // Print IP information if available
    if (packet.ethernet.ether_type == EthernetHeader::IPV4_TYPE) {
        std::cout << "\n  IP: " 
                  << PacketParser::ip_to_string(packet.ip.source) << " -> "
                  << PacketParser::ip_to_string(packet.ip.destination)
                  << " (TTL: " << static_cast<int>(packet.ip.ttl) << ")";
        
        // Print protocol information
        switch (packet.protocol) {
            case Protocol::TCP:
                std::cout << "\n  TCP: " << packet.transport.tcp.source_port 
                         << " -> " << packet.transport.tcp.destination_port;
                if (packet.transport.tcp.flags() & TcpHeader::SYN) std::cout << " [SYN]";
                if (packet.transport.tcp.flags() & TcpHeader::ACK) std::cout << " [ACK]";
                if (packet.transport.tcp.flags() & TcpHeader::FIN) std::cout << " [FIN]";
                if (packet.transport.tcp.flags() & TcpHeader::RST) std::cout << " [RST]";
                if (packet.transport.tcp.flags() & TcpHeader::PSH) std::cout << " [PSH]";
                break;
            case Protocol::UDP:
                std::cout << "\n  UDP: " << packet.transport.udp.source_port 
                         << " -> " << packet.transport.udp.destination_port;
                break;
            case Protocol::ICMP:
                std::cout << "\n  ICMP";
                break;
            default:
                std::cout << "\n  Protocol: " << static_cast<int>(packet.ip.protocol);
                break;
        }
        
        // Print packet size
        std::cout << " (Size: " << packet.metadata.length << " bytes)";
    }
    
    std::cout << std::endl << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "IntrDet - High-Performance Intrusion Detection Engine" << std::endl;
    std::cout << "=====================================================" << std::endl;
    
    // List available interfaces
    std::cout << "Available network interfaces:" << std::endl;
    auto interfaces = PacketSniffer::list_interfaces();
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << "  " << i << ": " << interfaces[i] << std::endl;
    }
    
    if (interfaces.empty()) {
        std::cerr << "No network interfaces found!" << std::endl;
        return 1;
    }
    
    // Select interface (use first one by default)
    std::string interface_name = interfaces[0];
    if (argc > 1) {
        interface_name = argv[1];
    } else {
        std::cout << "Using interface: " << interface_name << std::endl;
    }
    
    try {
        // Configure packet sniffer
        PacketSniffer::Config config;
        config.interface_name = interface_name;
        config.filter_expression = "ip"; // Only capture IP packets
        config.promiscuous = true;
        config.snap_length = MAX_PACKET_SIZE;
        config.timeout_ms = 1000;
        config.buffer_size = 64 * 1024 * 1024; // 64MB buffer
        
        // Create packet sniffer
        PacketSniffer sniffer(config);
        
        std::cout << "Starting packet capture on interface: " << interface_name << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        std::cout << "----------------------------------------" << std::endl;
        
        // Start packet capture
        if (!sniffer.start(packet_callback)) {
            std::cerr << "Failed to start packet capture!" << std::endl;
            return 1;
        }
        
        // Main loop - print statistics periodically
        auto last_stats_time = std::chrono::steady_clock::now();
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            auto now = std::chrono::steady_clock::now();
            if (now - last_stats_time >= std::chrono::seconds(10)) {
                auto stats = sniffer.get_statistics();
                std::cout << "\n=== Statistics ===" << std::endl;
                std::cout << "Packets captured: " << stats.packets_captured << std::endl;
                std::cout << "Packets dropped: " << stats.packets_dropped << std::endl;
                std::cout << "Capture rate: " << stats.capture_rate_pps << " pps" << std::endl;
                std::cout << "Drop rate: " << stats.drop_rate_percent << "%" << std::endl;
                std::cout << "==================" << std::endl << std::endl;
                
                last_stats_time = now;
            }
        }
        
        // Stop packet capture
        std::cout << "Stopping packet capture..." << std::endl;
        sniffer.stop();
        
        // Print final statistics
        auto final_stats = sniffer.get_statistics();
        std::cout << "\n=== Final Statistics ===" << std::endl;
        std::cout << "Total packets captured: " << final_stats.packets_captured << std::endl;
        std::cout << "Total packets dropped: " << final_stats.packets_dropped << std::endl;
        std::cout << "Average capture rate: " << final_stats.capture_rate_pps << " pps" << std::endl;
        std::cout << "Average drop rate: " << final_stats.drop_rate_percent << "%" << std::endl;
        std::cout << "=========================" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "IntrDet stopped successfully." << std::endl;
    return 0;
}

