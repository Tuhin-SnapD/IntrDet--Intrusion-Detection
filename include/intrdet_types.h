#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <chrono>
#include <memory>
#include <iostream>

namespace IntrDet {

// Network protocol constants
constexpr std::size_t MAX_PACKET_SIZE = 65536;
constexpr std::size_t ETH_HEADER_SIZE = 14;
constexpr std::size_t IP_HEADER_SIZE = 20;
constexpr std::size_t TCP_HEADER_SIZE = 20;
constexpr std::size_t UDP_HEADER_SIZE = 8;

// MAC address type
using MacAddress = std::array<uint8_t, 6>;
using IpAddress = std::array<uint8_t, 4>;
using Ipv6Address = std::array<uint8_t, 16>;

// Protocol types
enum class Protocol : uint8_t {
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    UNKNOWN = 0
};

// Packet metadata
struct PacketMetadata {
    std::chrono::steady_clock::time_point timestamp;
    uint32_t length;
    uint32_t captured_length;
    uint32_t interface_index;
    std::string interface_name;
};

// Ethernet header
struct EthernetHeader {
    MacAddress destination;
    MacAddress source;
    uint16_t ether_type;
    
    static constexpr uint16_t IPV4_TYPE = 0x0800;
    static constexpr uint16_t IPV6_TYPE = 0x86DD;
    static constexpr uint16_t ARP_TYPE = 0x0806;
};

// IP header
struct IpHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IpAddress source;
    IpAddress destination;
    
    uint8_t version() const { return (version_ihl >> 4) & 0x0F; }
    uint8_t ihl() const { return (version_ihl & 0x0F) * 4; }
    uint16_t flags() const { return (flags_offset >> 13) & 0x07; }
    uint16_t fragment_offset() const { return flags_offset & 0x1FFF; }
};

// TCP header
struct TcpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint16_t flags_offset;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    
    uint8_t data_offset() const { return (flags_offset >> 12) & 0x0F; }
    uint16_t flags() const { return flags_offset & 0x3FF; }
    
    // TCP flags
    static constexpr uint16_t FIN = 0x001;
    static constexpr uint16_t SYN = 0x002;
    static constexpr uint16_t RST = 0x004;
    static constexpr uint16_t PSH = 0x008;
    static constexpr uint16_t ACK = 0x010;
    static constexpr uint16_t URG = 0x020;
};

// UDP header
struct UdpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
};

// Parsed packet structure
struct ParsedPacket {
    PacketMetadata metadata;
    EthernetHeader ethernet;
    IpHeader ip;
    Protocol protocol;
    
    // Union for transport layer headers
    union {
        TcpHeader tcp;
        UdpHeader udp;
    } transport;
    
    // Payload data (zero-copy reference)
    const uint8_t* payload_data;
    uint32_t payload_length;
    
    // Helper methods
    bool is_tcp() const { return protocol == Protocol::TCP; }
    bool is_udp() const { return protocol == Protocol::UDP; }
    bool is_icmp() const { return protocol == Protocol::ICMP; }
    
    uint16_t source_port() const {
        if (is_tcp()) return transport.tcp.source_port;
        if (is_udp()) return transport.udp.source_port;
        return 0;
    }
    
    uint16_t destination_port() const {
        if (is_tcp()) return transport.tcp.destination_port;
        if (is_udp()) return transport.udp.destination_port;
        return 0;
    }
};

// Alert severity levels
enum class AlertSeverity : uint8_t {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Alert types
enum class AlertType : uint8_t {
    SYN_FLOOD,
    PORT_SCAN,
    ANOMALOUS_TRAFFIC,
    SUSPICIOUS_PAYLOAD,
    RATE_LIMIT_EXCEEDED,
    ML_ANOMALY
};

// Alert structure
struct Alert {
    std::chrono::steady_clock::time_point timestamp;
    AlertType type;
    AlertSeverity severity;
    std::string description;
    std::string source_ip;
    std::string destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    double confidence_score;
    std::string additional_data;
};

// Statistics structure
struct PacketStatistics {
    std::chrono::steady_clock::time_point window_start;
    uint64_t total_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t total_bytes;
    double packets_per_second;
    double bytes_per_second;
    double average_packet_size;
    
    // Reset statistics
    void reset() {
        total_packets = 0;
        tcp_packets = 0;
        udp_packets = 0;
        icmp_packets = 0;
        total_bytes = 0;
        packets_per_second = 0.0;
        bytes_per_second = 0.0;
        average_packet_size = 0.0;
    }
};

} // namespace IntrDet

// Stream operators for enums
inline std::ostream& operator<<(std::ostream& os, IntrDet::AlertType type) {
    switch (type) {
        case IntrDet::AlertType::SYN_FLOOD: return os << "SYN_FLOOD";
        case IntrDet::AlertType::PORT_SCAN: return os << "PORT_SCAN";
        case IntrDet::AlertType::ANOMALOUS_TRAFFIC: return os << "ANOMALOUS_TRAFFIC";
        case IntrDet::AlertType::SUSPICIOUS_PAYLOAD: return os << "SUSPICIOUS_PAYLOAD";
        case IntrDet::AlertType::RATE_LIMIT_EXCEEDED: return os << "RATE_LIMIT_EXCEEDED";
        case IntrDet::AlertType::ML_ANOMALY: return os << "ML_ANOMALY";
        default: return os << "UNKNOWN";
    }
}

inline std::ostream& operator<<(std::ostream& os, IntrDet::AlertSeverity severity) {
    switch (severity) {
        case IntrDet::AlertSeverity::LOW: return os << "LOW";
        case IntrDet::AlertSeverity::MEDIUM: return os << "MEDIUM";
        case IntrDet::AlertSeverity::HIGH: return os << "HIGH";
        case IntrDet::AlertSeverity::CRITICAL: return os << "CRITICAL";
        default: return os << "UNKNOWN";
    }
}

