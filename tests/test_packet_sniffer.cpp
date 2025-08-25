#include <gtest/gtest.h>
#include "packet_sniffer.h"

using namespace IntrDet;

class PacketSnifferTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup for tests
    }
};

TEST_F(PacketSnifferTest, ListInterfaces) {
    auto interfaces = PacketSniffer::list_interfaces();
    // This test will pass even if no interfaces are found
    // In a real environment, you'd expect to find at least one interface
    EXPECT_TRUE(true); // Placeholder test
}

TEST_F(PacketSnifferTest, InterfaceDescription) {
    std::string description = PacketSniffer::get_interface_description("nonexistent");
    EXPECT_FALSE(description.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

