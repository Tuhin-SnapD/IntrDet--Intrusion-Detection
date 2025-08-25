# Test configuration
if(ENABLE_TESTS)
    # Find GoogleTest
    find_package(GTest REQUIRED)
    
    # Test source files
    set(TEST_SOURCES
        test_packet_parser.cpp
        test_packet_sniffer.cpp
        test_processing_pipeline.cpp
        test_anomaly_detector.cpp
        test_alert_manager.cpp
    )
    
    # Create test executable
    add_executable(IntrDetTests ${TEST_SOURCES})
    
    # Link libraries
    target_link_libraries(IntrDetTests
        GTest::gtest
        GTest::gtest_main
        ${PCAP_LIBRARIES}
        Boost::system
        Boost::asio
        Threads::Threads
    )
    
    # Set compile definitions
    target_compile_definitions(IntrDetTests PRIVATE
        $<$<BOOL:${ENABLE_ML_INFERENCE}>:ENABLE_ML_INFERENCE>
    )
    
    # Link ONNX Runtime if available
    if(ENABLE_ML_INFERENCE)
        target_link_libraries(IntrDetTests ${ONNXRuntime_LIBRARIES})
        target_include_directories(IntrDetTests PRIVATE ${ONNXRuntime_INCLUDE_DIRS})
    endif()
    
    # Set properties
    set_target_properties(IntrDetTests PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    
    # Enable CTest
    enable_testing()
    add_test(NAME IntrDetTests COMMAND IntrDetTests)
    
    # Set test timeout
    set_tests_properties(IntrDetTests PROPERTIES TIMEOUT 300)
endif()

