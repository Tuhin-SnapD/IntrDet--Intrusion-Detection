#include <gtest/gtest.h>
#include "anomaly_detector.h"
#include <memory>

class AnomalyDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.rule_based_enabled = true;
        config.statistical_enabled = true;
        config.ml_enabled = false;
        config.alert_threshold = 0.8;
        config.window_size = 1000;
        
        detector = std::make_unique<AnomalyDetector>(config);
    }

    AnomalyDetector::Config config;
    std::unique_ptr<AnomalyDetector> detector;
};

TEST_F(AnomalyDetectorTest, Initialization) {
    EXPECT_TRUE(detector != nullptr);
    EXPECT_EQ(detector->get_config().rule_based_enabled, true);
    EXPECT_EQ(detector->get_config().statistical_enabled, true);
    EXPECT_EQ(detector->get_config().ml_enabled, false);
}

TEST_F(AnomalyDetectorTest, Configuration) {
    AnomalyDetector::Config new_config;
    new_config.rule_based_enabled = false;
    new_config.statistical_enabled = true;
    new_config.ml_enabled = true;
    new_config.alert_threshold = 0.9;
    new_config.window_size = 500;
    
    detector->update_config(new_config);
    
    EXPECT_EQ(detector->get_config().rule_based_enabled, false);
    EXPECT_EQ(detector->get_config().ml_enabled, true);
    EXPECT_EQ(detector->get_config().alert_threshold, 0.9);
}

TEST_F(AnomalyDetectorTest, StatisticsInitialization) {
    auto stats = detector->get_statistics();
    EXPECT_EQ(stats.total_packets_processed, 0);
    EXPECT_EQ(stats.alerts_generated, 0);
    EXPECT_EQ(stats.rule_based_alerts, 0);
    EXPECT_EQ(stats.statistical_alerts, 0);
    EXPECT_EQ(stats.ml_alerts, 0);
}

TEST_F(AnomalyDetectorTest, EmptyPacketProcessing) {
    ParsedPacket packet;
    packet.timestamp = std::chrono::steady_clock::now();
    packet.metadata.length = 0;
    
    bool alert_generated = false;
    detector->set_alert_callback([&alert_generated](const Alert& alert) {
        alert_generated = true;
    });
    
    detector->process_packet(packet);
    
    // Empty packet should not generate alerts
    EXPECT_FALSE(alert_generated);
}

TEST_F(AnomalyDetectorTest, ModelLoadingPlaceholder) {
    // Test that model loading doesn't crash
    EXPECT_NO_THROW(detector->load_ml_model("test_model.onnx"));
    
    // Test that invalid model path is handled gracefully
    EXPECT_NO_THROW(detector->load_ml_model("nonexistent_model.onnx"));
}
