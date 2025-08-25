#include <gtest/gtest.h>
#include "processing_pipeline.h"

using namespace IntrDet;

class ProcessingPipelineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup for tests
    }
};

TEST_F(ProcessingPipelineTest, BasicFunctionality) {
    ProcessingPipeline::Config config;
    config.num_workers = 2;
    config.queue_size = 100;
    
    ProcessingPipeline pipeline(config);
    EXPECT_FALSE(pipeline.is_running());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

