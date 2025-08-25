#pragma once

#include "intrdet_types.h"
#include <cstdint>
#include <string>
#include <optional>

namespace IntrDet {

/**
 * @brief High-performance packet parser for network protocols
 * 
 * This class provides efficient parsing of network packet headers:
 * - Ethernet frame parsing
 * - IP header parsing (IPv4/IPv6)
 * - TCP/UDP header parsing
 * - Zero-copy parsing where possible
 * - Validation and error checking
 */
class PacketParser {
public:
    /**
     * @brief Parse a raw packet into structured data
     * @param packet_data Raw packet data
     * @param packet_length Length of packet data
     * @param metadata Packet metadata
     * @return Parsed packet or nullopt if parsing failed
     */
    static std::optional<ParsedPacket> parse_packet(
        const uint8_t* packet_data,
        uint32_t packet_length,
        const PacketMetadata& metadata
    );

    /**
     * @brief Parse Ethernet header
     * @param data Pointer to Ethernet header data
     * @param length Available data length
     * @return Parsed Ethernet header or nullopt if invalid
     */
    static std::optional<EthernetHeader> parse_ethernet_header(
        const uint8_t* data,
        uint32_t length
    );

    /**
     * @brief Parse IP header
     * @param data Pointer to IP header data
     * @param length Available data length
     * @return Parsed IP header or nullopt if invalid
     */
    static std::optional<IpHeader> parse_ip_header(
        const uint8_t* data,
        uint32_t length
    );

    /**
     * @brief Parse TCP header
     * @param data Pointer to TCP header data
     * @param length Available data length
     * @return Parsed TCP header or nullopt if invalid
     */
    static std::optional<TcpHeader> parse_tcp_header(
        const uint8_t* data,
        uint32_t length
    );

    /**
     * @brief Parse UDP header
     * @param data Pointer to UDP header data
     * @param length Available data length
     * @return Parsed UDP header or nullopt if invalid
     */
    static std::optional<UdpHeader> parse_udp_header(
        const uint8_t* data,
        uint32_t length
    );

    /**
     * @brief Convert IP address to string
     * @param ip IP address array
     * @return String representation
     */
    static std::string ip_to_string(const IpAddress& ip);

    /**
     * @brief Convert MAC address to string
     * @param mac MAC address array
     * @return String representation
     */
    static std::string mac_to_string(const MacAddress& mac);

    /**
     * @brief Calculate IP header checksum
     * @param header IP header
     * @return Calculated checksum
     */
    static uint16_t calculate_ip_checksum(const IpHeader& header);

    /**
     * @brief Calculate TCP checksum
     * @param tcp_header TCP header
     * @param ip_header IP header
     * @param payload_data Payload data
     * @param payload_length Payload length
     * @return Calculated checksum
     */
    static uint16_t calculate_tcp_checksum(
        const TcpHeader& tcp_header,
        const IpHeader& ip_header,
        const uint8_t* payload_data,
        uint32_t payload_length
    );

    /**
     * @brief Validate packet structure
     * @param packet Parsed packet to validate
     * @return true if packet is valid
     */
    static bool validate_packet(const ParsedPacket& packet);

private:
    /**
     * @brief Calculate Internet checksum
     * @param data Data to checksum
     * @param length Length of data
     * @return Calculated checksum
     */
    static uint16_t internet_checksum(const uint8_t* data, uint32_t length);

    /**
     * @brief Check if packet length is sufficient for header
     * @param available Available data length
     * @param required Required header length
     * @return true if sufficient data available
     */
    static bool check_length(uint32_t available, uint32_t required) {
        return available >= required;
    }
};

} // namespace IntrDet

