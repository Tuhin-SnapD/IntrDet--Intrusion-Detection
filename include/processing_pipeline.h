#pragma once

#include "intrdet_types.h"
#include <atomic>
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <memory>
#include <mutex>
#include <condition_variable>
#include "mock_boost.h"

namespace IntrDet {

/**
 * @brief Lock-free packet processing pipeline
 * 
 * This class implements a high-performance processing pipeline with:
 * - Lock-free queues for packet events
 * - Multi-threaded worker pool
 * - Configurable processing stages
 * - Rolling statistics collection
 * - Zero-copy packet passing where possible
 */
class ProcessingPipeline {
public:
    // Processing stage callback type
    using ProcessingStage = std::function<void(const ParsedPacket&)>;
    
    // Configuration structure
    struct Config {
        size_t num_workers;
        size_t queue_size;
        size_t batch_size;
        std::chrono::milliseconds worker_timeout;
        bool enable_statistics;
        std::chrono::seconds statistics_window;
        
        Config() 
            : num_workers(std::thread::hardware_concurrency())
            , queue_size(10000)
            , batch_size(100)
            , worker_timeout(100)
            , enable_statistics(true)
            , statistics_window(60) {}
    };

    explicit ProcessingPipeline(const Config& config = Config{});
    ~ProcessingPipeline();

    // Disable copy
    ProcessingPipeline(const ProcessingPipeline&) = delete;
    ProcessingPipeline& operator=(const ProcessingPipeline&) = delete;

    // Allow move
    ProcessingPipeline(ProcessingPipeline&&) noexcept;
    ProcessingPipeline& operator=(ProcessingPipeline&&) noexcept;

    /**
     * @brief Add a processing stage to the pipeline
     * @param stage_name Name of the stage
     * @param stage_func Processing function
     */
    void add_stage(const std::string& stage_name, ProcessingStage stage_func);

    /**
     * @brief Start the processing pipeline
     */
    void start();

    /**
     * @brief Stop the processing pipeline
     */
    void stop();

    /**
     * @brief Submit a packet for processing
     * @param packet Packet to process
     * @return true if packet was queued successfully
     */
    bool submit_packet(const ParsedPacket& packet);

    /**
     * @brief Check if pipeline is running
     */
    bool is_running() const { return running_.load(); }

    /**
     * @brief Get pipeline statistics
     */
    struct PipelineStatistics {
        uint64_t packets_processed;
        uint64_t packets_dropped;
        uint64_t queue_full_count;
        double processing_rate_pps;
        double average_processing_time_ms;
        std::chrono::steady_clock::time_point last_update;
        
        // Per-stage statistics
        struct StageStats {
            std::string name;
            uint64_t packets_processed;
            double average_processing_time_ms;
            uint64_t errors;
        };
        std::vector<StageStats> stage_statistics;
    };
    
    PipelineStatistics get_statistics() const;

    /**
     * @brief Get current queue depth
     */
    size_t get_queue_depth() const;

private:
    // Worker thread function
    void worker_thread(size_t worker_id);
    
    // Process a batch of packets
    void process_batch(std::vector<ParsedPacket>& batch);
    
    // Update statistics
    void update_statistics();
    
    // Configuration
    Config config_;
    
    // Processing stages
    struct Stage {
        std::string name;
        ProcessingStage function;
        std::atomic<uint64_t> packets_processed{0};
        std::atomic<uint64_t> errors{0};
        std::atomic<double> total_processing_time{0.0};
        
        // Make Stage movable
        Stage() = default;
        Stage(const Stage&) = delete;
        Stage& operator=(const Stage&) = delete;
        Stage(Stage&& other) noexcept 
            : name(std::move(other.name))
            , function(std::move(other.function))
            , packets_processed(other.packets_processed.load())
            , errors(other.errors.load())
            , total_processing_time(other.total_processing_time.load()) {}
        
        Stage(const std::string& n, ProcessingStage f) 
            : name(n)
            , function(std::move(f))
            , packets_processed(0)
            , errors(0)
            , total_processing_time(0.0) {}
        Stage& operator=(Stage&& other) noexcept {
            if (this != &other) {
                name = std::move(other.name);
                function = std::move(other.function);
                packets_processed.store(other.packets_processed.load());
                errors.store(other.errors.load());
                total_processing_time.store(other.total_processing_time.load());
            }
            return *this;
        }
    };
    std::vector<Stage> stages_;
    
    // Lock-free queue for packet processing
    using PacketQueue = boost::lockfree::queue<ParsedPacket, 10000>;
    std::unique_ptr<PacketQueue> packet_queue_;
    
    // Worker threads
    std::vector<std::thread> workers_;
    std::atomic<bool> running_;
    std::atomic<bool> should_stop_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    PipelineStatistics stats_;
    std::chrono::steady_clock::time_point last_stats_update_;
    
    // Batch processing
    std::vector<std::vector<ParsedPacket>> worker_batches_;
    
    // Performance counters
    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> packets_dropped_{0};
    std::atomic<uint64_t> queue_full_count_{0};
    std::atomic<double> total_processing_time_{0.0};
};

/**
 * @brief Lock-free ring buffer for high-performance packet storage
 */
template<typename T, size_t Size>
class LockFreeRingBuffer {
public:
    static_assert(Size > 0 && ((Size & (Size - 1)) == 0), "Size must be a power of 2");
    
    LockFreeRingBuffer() : head_(0), tail_(0) {}
    
    /**
     * @brief Try to push an item to the buffer
     * @param item Item to push
     * @return true if successful
     */
    bool try_push(const T& item) {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next_head = (head + 1) & (Size - 1);
        
        if (next_head == tail_.load(std::memory_order_acquire)) {
            return false; // Buffer full
        }
        
        buffer_[head] = item;
        head_.store(next_head, std::memory_order_release);
        return true;
    }
    
    /**
     * @brief Try to pop an item from the buffer
     * @param item Reference to store popped item
     * @return true if successful
     */
    bool try_pop(T& item) {
        size_t tail = tail_.load(std::memory_order_relaxed);
        
        if (tail == head_.load(std::memory_order_acquire)) {
            return false; // Buffer empty
        }
        
        item = buffer_[tail];
        tail_.store((tail + 1) & (Size - 1), std::memory_order_release);
        return true;
    }
    
    /**
     * @brief Check if buffer is empty
     */
    bool empty() const {
        return head_.load(std::memory_order_acquire) == 
               tail_.load(std::memory_order_acquire);
    }
    
    /**
     * @brief Check if buffer is full
     */
    bool full() const {
        size_t next_head = (head_.load(std::memory_order_relaxed) + 1) & (Size - 1);
        return next_head == tail_.load(std::memory_order_acquire);
    }
    
    /**
     * @brief Get current size
     */
    size_t size() const {
        size_t head = head_.load(std::memory_order_acquire);
        size_t tail = tail_.load(std::memory_order_acquire);
        return (head - tail) & (Size - 1);
    }

private:
    std::array<T, Size> buffer_;
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
};

} // namespace IntrDet

