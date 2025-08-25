# Source files
set(SOURCES
    main.cpp
    packet_sniffer.cpp
    packet_parser.cpp
    processing_pipeline.cpp
    anomaly_detector.cpp
    alert_manager.cpp
)

# Header files
set(HEADERS
    packet_sniffer.h
    packet_parser.h
    processing_pipeline.h
    anomaly_detector.h
    alert_manager.h
)

# Create the main executable
add_executable(IntrDet ${SOURCES})

# Link libraries
target_link_libraries(IntrDet
    ${PCAP_LIBRARIES}
    Boost::system
    Boost::asio
    Threads::Threads
)

# Set compile definitions
target_compile_definitions(IntrDet PRIVATE
    $<$<BOOL:${ENABLE_ML_INFERENCE}>:ENABLE_ML_INFERENCE>
)

# Link ONNX Runtime if available
if(ENABLE_ML_INFERENCE)
    target_link_libraries(IntrDet ${ONNXRuntime_LIBRARIES})
    target_include_directories(IntrDet PRIVATE ${ONNXRuntime_INCLUDE_DIRS})
endif()

# Set properties
set_target_properties(IntrDet PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

