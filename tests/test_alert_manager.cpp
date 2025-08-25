#include <gtest/gtest.h>
#include "alert_manager.h"
#include <memory>

class AlertManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.rate_limit_per_second = 100;
        config.deduplication_window_ms = 5000;
        config.persistence_enabled = true;
        config.json_output_enabled = true;
        config.rest_api_enabled = false;
        config.grpc_enabled = false;
        config.websocket_enabled = false;
        
        manager = std::make_unique<AlertManager>(config);
    }

    AlertManager::Config config;
    std::unique_ptr<AlertManager> manager;
};

TEST_F(AlertManagerTest, Initialization) {
    EXPECT_TRUE(manager != nullptr);
    EXPECT_EQ(manager->get_config().rate_limit_per_second, 100);
    EXPECT_EQ(manager->get_config().deduplication_window_ms, 5000);
    EXPECT_EQ(manager->get_config().persistence_enabled, true);
}

TEST_F(AlertManagerTest, Configuration) {
    AlertManager::Config new_config;
    new_config.rate_limit_per_second = 200;
    new_config.deduplication_window_ms = 10000;
    new_config.persistence_enabled = false;
    new_config.json_output_enabled = true;
    
    manager->update_config(new_config);
    
    EXPECT_EQ(manager->get_config().rate_limit_per_second, 200);
    EXPECT_EQ(manager->get_config().deduplication_window_ms, 10000);
    EXPECT_EQ(manager->get_config().persistence_enabled, false);
}

TEST_F(AlertManagerTest, AlertSubmission) {
    Alert alert;
    alert.id = "test_alert_001";
    alert.timestamp = std::chrono::steady_clock::now();
    alert.severity = AlertSeverity::HIGH;
    alert.type = AlertType::SYN_FLOOD;
    alert.description = "Test SYN flood alert";
    alert.source_ip = IpAddress{192, 168, 1, 100};
    alert.destination_ip = IpAddress{192, 168, 1, 1};
    alert.confidence_score = 0.85;
    
    bool alert_received = false;
    manager->set_alert_output_callback([&alert_received](const std::string& output) {
        alert_received = true;
        EXPECT_FALSE(output.empty());
    });
    
    manager->submit_alert(alert);
    
    // Alert should be processed
    EXPECT_TRUE(alert_received);
}

TEST_F(AlertManagerTest, StatisticsInitialization) {
    auto stats = manager->get_statistics();
    EXPECT_EQ(stats.total_alerts_submitted, 0);
    EXPECT_EQ(stats.alerts_rate_limited, 0);
    EXPECT_EQ(stats.alerts_deduplicated, 0);
    EXPECT_EQ(stats.alerts_persisted, 0);
    EXPECT_EQ(stats.alerts_sent_via_json, 0);
    EXPECT_EQ(stats.alerts_sent_via_rest, 0);
    EXPECT_EQ(stats.alerts_sent_via_grpc, 0);
    EXPECT_EQ(stats.alerts_sent_via_websocket, 0);
}

TEST_F(AlertManagerTest, AlertDeduplication) {
    Alert alert1, alert2;
    alert1.id = "duplicate_alert";
    alert1.timestamp = std::chrono::steady_clock::now();
    alert1.severity = AlertSeverity::MEDIUM;
    alert1.type = AlertType::PORT_SCAN;
    alert1.description = "Port scan detected";
    
    alert2 = alert1; // Same alert
    
    int alert_count = 0;
    manager->set_alert_output_callback([&alert_count](const std::string& output) {
        alert_count++;
    });
    
    manager->submit_alert(alert1);
    manager->submit_alert(alert2);
    
    // Only one alert should be processed due to deduplication
    EXPECT_EQ(alert_count, 1);
}

TEST_F(AlertManagerTest, AlertJsonFormatter) {
    Alert alert;
    alert.id = "json_test_alert";
    alert.timestamp = std::chrono::steady_clock::now();
    alert.severity = AlertSeverity::CRITICAL;
    alert.type = AlertType::MALWARE_DETECTED;
    alert.description = "Malware signature detected";
    alert.source_ip = IpAddress{10, 0, 0, 50};
    alert.destination_ip = IpAddress{10, 0, 0, 1};
    alert.confidence_score = 0.95;
    
    std::string json_output = AlertJsonFormatter::format(alert);
    
    EXPECT_FALSE(json_output.empty());
    EXPECT_NE(json_output.find("json_test_alert"), std::string::npos);
    EXPECT_NE(json_output.find("CRITICAL"), std::string::npos);
    EXPECT_NE(json_output.find("MALWARE_DETECTED"), std::string::npos);
    EXPECT_NE(json_output.find("10.0.0.50"), std::string::npos);
}

TEST_F(AlertManagerTest, SeverityCalculation) {
    Alert alert;
    alert.confidence_score = 0.9;
    alert.type = AlertType::DDOS_ATTACK;
    
    // High confidence + critical alert type should result in high severity
    AlertSeverity severity = manager->calculate_severity(alert);
    EXPECT_GE(severity, AlertSeverity::HIGH);
}

TEST_F(AlertManagerTest, RateLimitingPlaceholder) {
    // Test that rate limiting doesn't crash
    for (int i = 0; i < 150; ++i) {
        Alert alert;
        alert.id = "rate_limit_test_" + std::to_string(i);
        alert.timestamp = std::chrono::steady_clock::now();
        alert.severity = AlertSeverity::LOW;
        alert.type = AlertType::UNUSUAL_TRAFFIC;
        
        EXPECT_NO_THROW(manager->submit_alert(alert));
    }
}
