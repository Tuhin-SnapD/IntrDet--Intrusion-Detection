#include <gtest/gtest.h>
#include "packet_parser.h"
#include <cstring>

using namespace IntrDet;

class PacketParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a sample Ethernet + IP + TCP packet
        create_sample_packet();
    }
    
    void create_sample_packet() {
        // Ethernet header (14 bytes)
        uint8_t eth_header[] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Destination MAC
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Source MAC
            0x08, 0x00                           // EtherType (IPv4)
        };
        
        // IP header (20 bytes)
        uint8_t ip_header[] = {
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,  // Version, IHL, ToS, Total Length, ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00,                          // TTL, Protocol (TCP), Checksum
            0xC0, 0xA8, 0x01, 0x01,                          // Source IP (192.168.1.1)
            0xC0, 0xA8, 0x01, 0x02                           // Destination IP (192.168.1.2)
        };
        
        // TCP header (20 bytes)
        uint8_t tcp_header[] = {
            0x12, 0x34, 0x56, 0x78,                          // Source Port (4660), Destination Port (22136)
            0x00, 0x00, 0x00, 0x01,                          // Sequence Number
            0x00, 0x00, 0x00, 0x00,                          // Acknowledgment Number
            0x50, 0x02, 0x20, 0x00,                          // Data Offset, Flags (SYN), Window Size
            0x00, 0x00, 0x00, 0x00                           // Checksum, Urgent Pointer
        };
        
        // Combine all headers
        std::memcpy(sample_packet, eth_header, sizeof(eth_header));
        std::memcpy(sample_packet + sizeof(eth_header), ip_header, sizeof(ip_header));
        std::memcpy(sample_packet + sizeof(eth_header) + sizeof(ip_header), tcp_header, sizeof(tcp_header));
        
        packet_length = sizeof(eth_header) + sizeof(ip_header) + sizeof(tcp_header);
    }
    
    uint8_t sample_packet[64];
    uint32_t packet_length;
};

TEST_F(PacketParserTest, ParseEthernetHeader) {
    auto eth_header = PacketParser::parse_ethernet_header(sample_packet, packet_length);
    
    ASSERT_TRUE(eth_header.has_value());
    EXPECT_EQ(eth_header->ether_type, EthernetHeader::IPV4_TYPE);
    
    // Check MAC addresses
    EXPECT_EQ(eth_header->destination[0], 0x00);
    EXPECT_EQ(eth_header->destination[1], 0x11);
    EXPECT_EQ(eth_header->source[0], 0x66);
    EXPECT_EQ(eth_header->source[1], 0x77);
}

TEST_F(PacketParserTest, ParseIPHeader) {
    const uint8_t* ip_data = sample_packet + ETH_HEADER_SIZE;
    auto ip_header = PacketParser::parse_ip_header(ip_data, packet_length - ETH_HEADER_SIZE);
    
    ASSERT_TRUE(ip_header.has_value());
    EXPECT_EQ(ip_header->version(), 4);
    EXPECT_EQ(ip_header->protocol, 6); // TCP
    EXPECT_EQ(ip_header->ttl, 64);
    
    // Check IP addresses
    EXPECT_EQ(ip_header->source[0], 192);
    EXPECT_EQ(ip_header->source[1], 168);
    EXPECT_EQ(ip_header->source[2], 1);
    EXPECT_EQ(ip_header->source[3], 1);
    
    EXPECT_EQ(ip_header->destination[0], 192);
    EXPECT_EQ(ip_header->destination[1], 168);
    EXPECT_EQ(ip_header->destination[2], 1);
    EXPECT_EQ(ip_header->destination[3], 2);
}

TEST_F(PacketParserTest, ParseTCPHeader) {
    const uint8_t* tcp_data = sample_packet + ETH_HEADER_SIZE + IP_HEADER_SIZE;
    auto tcp_header = PacketParser::parse_tcp_header(tcp_data, packet_length - ETH_HEADER_SIZE - IP_HEADER_SIZE);
    
    ASSERT_TRUE(tcp_header.has_value());
    EXPECT_EQ(tcp_header->source_port, 4660);
    EXPECT_EQ(tcp_header->destination_port, 22136);
    EXPECT_EQ(tcp_header->data_offset(), 5);
    EXPECT_TRUE(tcp_header->flags() & TcpHeader::SYN);
}

TEST_F(PacketParserTest, ParseCompletePacket) {
    PacketMetadata metadata;
    metadata.timestamp = std::chrono::steady_clock::now();
    metadata.length = packet_length;
    metadata.captured_length = packet_length;
    metadata.interface_index = 0;
    metadata.interface_name = "test";
    
    auto parsed_packet = PacketParser::parse_packet(sample_packet, packet_length, metadata);
    
    ASSERT_TRUE(parsed_packet.has_value());
    EXPECT_EQ(parsed_packet->protocol, Protocol::TCP);
    EXPECT_EQ(parsed_packet->source_port(), 4660);
    EXPECT_EQ(parsed_packet->destination_port(), 22136);
    EXPECT_TRUE(parsed_packet->is_tcp());
}

TEST_F(PacketParserTest, IPToString) {
    IpAddress ip = {192, 168, 1, 1};
    std::string ip_str = PacketParser::ip_to_string(ip);
    EXPECT_EQ(ip_str, "192.168.1.1");
}

TEST_F(PacketParserTest, MACToString) {
    MacAddress mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::string mac_str = PacketParser::mac_to_string(mac);
    EXPECT_EQ(mac_str, "00:11:22:33:44:55");
}

TEST_F(PacketParserTest, InvalidPacketLength) {
    PacketMetadata metadata;
    metadata.timestamp = std::chrono::steady_clock::now();
    metadata.length = 10; // Too short
    metadata.captured_length = 10;
    metadata.interface_index = 0;
    metadata.interface_name = "test";
    
    auto parsed_packet = PacketParser::parse_packet(sample_packet, 10, metadata);
    EXPECT_FALSE(parsed_packet.has_value());
}

TEST_F(PacketParserTest, ValidatePacket) {
    PacketMetadata metadata;
    metadata.timestamp = std::chrono::steady_clock::now();
    metadata.length = packet_length;
    metadata.captured_length = packet_length;
    metadata.interface_index = 0;
    metadata.interface_name = "test";
    
    auto parsed_packet = PacketParser::parse_packet(sample_packet, packet_length, metadata);
    ASSERT_TRUE(parsed_packet.has_value());
    
    EXPECT_TRUE(PacketParser::validate_packet(*parsed_packet));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

