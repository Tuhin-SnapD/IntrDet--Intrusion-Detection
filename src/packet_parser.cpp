#include "packet_parser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace IntrDet {

std::optional<ParsedPacket> PacketParser::parse_packet(
    const uint8_t* packet_data,
    uint32_t packet_length,
    const PacketMetadata& metadata
) {
    if (!packet_data || packet_length < ETH_HEADER_SIZE) {
        return std::nullopt;
    }
    
    ParsedPacket parsed_packet;
    parsed_packet.metadata = metadata;
    parsed_packet.payload_data = nullptr;
    parsed_packet.payload_length = 0;
    
    // Parse Ethernet header
    auto eth_header = parse_ethernet_header(packet_data, packet_length);
    if (!eth_header) {
        return std::nullopt;
    }
    parsed_packet.ethernet = *eth_header;
    
    // Check if this is an IP packet
    if (eth_header->ether_type != EthernetHeader::IPV4_TYPE) {
        // Not an IP packet, but still valid Ethernet frame
        parsed_packet.protocol = Protocol::UNKNOWN;
        return parsed_packet;
    }
    
    // Parse IP header
    const uint8_t* ip_data = packet_data + ETH_HEADER_SIZE;
    uint32_t ip_data_length = packet_length - ETH_HEADER_SIZE;
    
    auto ip_header = parse_ip_header(ip_data, ip_data_length);
    if (!ip_header) {
        return std::nullopt;
    }
    parsed_packet.ip = *ip_header;
    
    // Determine protocol
    switch (ip_header->protocol) {
        case 6:  // TCP
            parsed_packet.protocol = Protocol::TCP;
            break;
        case 17: // UDP
            parsed_packet.protocol = Protocol::UDP;
            break;
        case 1:  // ICMP
            parsed_packet.protocol = Protocol::ICMP;
            break;
        default:
            parsed_packet.protocol = Protocol::UNKNOWN;
            return parsed_packet;
    }
    
    // Parse transport layer header
    const uint8_t* transport_data = ip_data + ip_header->ihl();
    uint32_t transport_data_length = ip_data_length - ip_header->ihl();
    
    switch (parsed_packet.protocol) {
        case Protocol::TCP: {
            auto tcp_header = parse_tcp_header(transport_data, transport_data_length);
            if (!tcp_header) {
                return std::nullopt;
            }
            parsed_packet.transport.tcp = *tcp_header;
            
            // Set payload data
            uint32_t tcp_header_size = tcp_header->data_offset() * 4;
            if (transport_data_length > tcp_header_size) {
                parsed_packet.payload_data = transport_data + tcp_header_size;
                parsed_packet.payload_length = transport_data_length - tcp_header_size;
            }
            break;
        }
        case Protocol::UDP: {
            auto udp_header = parse_udp_header(transport_data, transport_data_length);
            if (!udp_header) {
                return std::nullopt;
            }
            parsed_packet.transport.udp = *udp_header;
            
            // Set payload data
            if (transport_data_length > UDP_HEADER_SIZE) {
                parsed_packet.payload_data = transport_data + UDP_HEADER_SIZE;
                parsed_packet.payload_length = transport_data_length - UDP_HEADER_SIZE;
            }
            break;
        }
        case Protocol::ICMP: {
            // ICMP doesn't have ports, so we don't parse transport header
            if (transport_data_length > 0) {
                parsed_packet.payload_data = transport_data;
                parsed_packet.payload_length = transport_data_length;
            }
            break;
        }
        default:
            break;
    }
    
    return parsed_packet;
}

std::optional<EthernetHeader> PacketParser::parse_ethernet_header(
    const uint8_t* data,
    uint32_t length
) {
    if (!check_length(length, ETH_HEADER_SIZE)) {
        return std::nullopt;
    }
    
    EthernetHeader header;
    
    // Parse destination MAC address
    std::memcpy(header.destination.data(), data, 6);
    
    // Parse source MAC address
    std::memcpy(header.source.data(), data + 6, 6);
    
    // Parse ethernet type (network byte order)
    header.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
    
    return header;
}

std::optional<IpHeader> PacketParser::parse_ip_header(
    const uint8_t* data,
    uint32_t length
) {
    if (!check_length(length, IP_HEADER_SIZE)) {
        return std::nullopt;
    }
    
    IpHeader header;
    
    // Parse version and IHL
    header.version_ihl = data[0];
    
    // Check IP version
    if (header.version() != 4) {
        return std::nullopt; // Only IPv4 supported for now
    }
    
    // Check minimum header length
    if (header.ihl() < IP_HEADER_SIZE) {
        return std::nullopt;
    }
    
    // Parse remaining fields
    header.tos = data[1];
    header.total_length = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.identification = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    header.flags_offset = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    header.ttl = data[8];
    header.protocol = data[9];
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));
    
    // Parse IP addresses
    std::memcpy(header.source.data(), data + 12, 4);
    std::memcpy(header.destination.data(), data + 16, 4);
    
    return header;
}

std::optional<TcpHeader> PacketParser::parse_tcp_header(
    const uint8_t* data,
    uint32_t length
) {
    if (!check_length(length, TCP_HEADER_SIZE)) {
        return std::nullopt;
    }
    
    TcpHeader header;
    
    // Parse ports
    header.source_port = ntohs(*reinterpret_cast<const uint16_t*>(data));
    header.destination_port = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    
    // Parse sequence and acknowledgment numbers
    header.sequence_number = ntohl(*reinterpret_cast<const uint32_t*>(data + 4));
    header.acknowledgment_number = ntohl(*reinterpret_cast<const uint32_t*>(data + 8));
    
    // Parse flags and offset
    header.flags_offset = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
    
    // Check data offset
    if (header.data_offset() < 5) { // Minimum TCP header size is 20 bytes (5 * 4)
        return std::nullopt;
    }
    
    // Parse remaining fields
    header.window_size = ntohs(*reinterpret_cast<const uint16_t*>(data + 14));
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 16));
    header.urgent_pointer = ntohs(*reinterpret_cast<const uint16_t*>(data + 18));
    
    return header;
}

std::optional<UdpHeader> PacketParser::parse_udp_header(
    const uint8_t* data,
    uint32_t length
) {
    if (!check_length(length, UDP_HEADER_SIZE)) {
        return std::nullopt;
    }
    
    UdpHeader header;
    
    // Parse ports
    header.source_port = ntohs(*reinterpret_cast<const uint16_t*>(data));
    header.destination_port = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    
    // Parse length and checksum
    header.length = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    
    return header;
}

std::string PacketParser::ip_to_string(const IpAddress& ip) {
    std::ostringstream oss;
    oss << static_cast<int>(ip[0]) << "."
        << static_cast<int>(ip[1]) << "."
        << static_cast<int>(ip[2]) << "."
        << static_cast<int>(ip[3]);
    return oss.str();
}

std::string PacketParser::mac_to_string(const MacAddress& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(2);
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i > 0) oss << ":";
        oss << static_cast<int>(mac[i]);
    }
    return oss.str();
}

uint16_t PacketParser::calculate_ip_checksum(const IpHeader& header) {
    // Create a copy of the header with checksum field set to 0
    IpHeader temp_header = header;
    temp_header.checksum = 0;
    
    // Calculate checksum over the header
    return internet_checksum(reinterpret_cast<const uint8_t*>(&temp_header), sizeof(IpHeader));
}

uint16_t PacketParser::calculate_tcp_checksum(
    const TcpHeader& tcp_header,
    const IpHeader& ip_header,
    const uint8_t* payload_data,
    uint32_t payload_length
) {
    // TCP pseudo-header for checksum calculation
    struct {
        IpAddress source;
        IpAddress destination;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;
    
    pseudo_header.source = ip_header.source;
    pseudo_header.destination = ip_header.destination;
    pseudo_header.zero = 0;
    pseudo_header.protocol = 6; // TCP
    pseudo_header.tcp_length = htons(sizeof(TcpHeader) + payload_length);
    
    // Calculate checksum over pseudo-header + TCP header + payload
    uint32_t total_length = sizeof(pseudo_header) + sizeof(TcpHeader) + payload_length;
    std::vector<uint8_t> buffer(total_length);
    
    // Ensure buffer is not empty
    if (buffer.empty()) {
        return 0;
    }
    
    // Copy pseudo-header
    std::memcpy(buffer.data(), &pseudo_header, sizeof(pseudo_header));
    
    // Copy TCP header with checksum set to 0
    TcpHeader temp_tcp = tcp_header;
    temp_tcp.checksum = 0;
    std::memcpy(buffer.data() + sizeof(pseudo_header), &temp_tcp, sizeof(TcpHeader));
    
    // Copy payload if present
    if (payload_data && payload_length > 0) {
        std::memcpy(buffer.data() + sizeof(pseudo_header) + sizeof(TcpHeader), 
                   payload_data, payload_length);
    }
    
    return internet_checksum(buffer.data(), total_length);
}

bool PacketParser::validate_packet(const ParsedPacket& packet) {
    // Basic validation checks
    if (packet.metadata.length == 0 || packet.metadata.captured_length == 0) {
        return false;
    }
    
    if (packet.metadata.captured_length > packet.metadata.length) {
        return false;
    }
    
    // Validate IP header if present
    if (packet.ethernet.ether_type == EthernetHeader::IPV4_TYPE) {
        if (packet.ip.version() != 4) {
            return false;
        }
        
        if (packet.ip.ihl() < IP_HEADER_SIZE / 4) {
            return false;
        }
        
        // Validate checksum if needed
        // Note: This is expensive, so we might want to make it optional
        // uint16_t calculated_checksum = calculate_ip_checksum(packet.ip);
        // if (calculated_checksum != 0 && calculated_checksum != packet.ip.checksum) {
        //     return false;
        // }
    }
    
    // Validate TCP header if present
    if (packet.protocol == Protocol::TCP) {
        if (packet.transport.tcp.data_offset() < 5) {
            return false;
        }
    }
    
    return true;
}

uint16_t PacketParser::internet_checksum(const uint8_t* data, uint32_t length) {
    uint32_t sum = 0;
    
    // Sum 16-bit words
    for (uint32_t i = 0; i < length - 1; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    
    // Handle odd byte if present
    if (length & 1) {
        sum += data[length - 1] << 8;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Take one's complement
    return static_cast<uint16_t>(~sum);
}

} // namespace IntrDet

