#include "processing_pipeline.h"
#include <iostream>

namespace IntrDet {

ProcessingPipeline::ProcessingPipeline(const Config& config)
    : config_(config)
    , packet_queue_(std::make_unique<PacketQueue>())
    , running_(false)
    , should_stop_(false)
{
    // Initialize worker batches
    worker_batches_.resize(config.num_workers);
    for (auto& batch : worker_batches_) {
        batch.reserve(config.batch_size);
    }
}

ProcessingPipeline::~ProcessingPipeline() {
    stop();
}

ProcessingPipeline::ProcessingPipeline(ProcessingPipeline&& other) noexcept
    : config_(std::move(other.config_))
    , stages_(std::move(other.stages_))
    , packet_queue_(std::move(other.packet_queue_))
    , workers_(std::move(other.workers_))
    , running_(other.running_.load())
    , should_stop_(other.should_stop_.load())
    , stats_(std::move(other.stats_))
    , last_stats_update_(std::move(other.last_stats_update_))
    , worker_batches_(std::move(other.worker_batches_))
{
    other.running_ = false;
    other.should_stop_ = false;
}

ProcessingPipeline& ProcessingPipeline::operator=(ProcessingPipeline&& other) noexcept {
    if (this != &other) {
        stop();
        
        config_ = std::move(other.config_);
        stages_ = std::move(other.stages_);
        packet_queue_ = std::move(other.packet_queue_);
        workers_ = std::move(other.workers_);
        running_ = other.running_.load();
        should_stop_ = other.should_stop_.load();
        stats_ = std::move(other.stats_);
        last_stats_update_ = std::move(other.last_stats_update_);
        worker_batches_ = std::move(other.worker_batches_);
        
        other.running_ = false;
        other.should_stop_ = false;
    }
    return *this;
}

void ProcessingPipeline::add_stage(const std::string& stage_name, ProcessingStage stage_func) {
    stages_.push_back({stage_name, std::move(stage_func)});
}

void ProcessingPipeline::start() {
    if (running_.load()) {
        return;
    }
    
    running_ = true;
    should_stop_ = false;
    
    // Start worker threads
    for (size_t i = 0; i < config_.num_workers; ++i) {
        workers_.emplace_back(&ProcessingPipeline::worker_thread, this, i);
    }
}

void ProcessingPipeline::stop() {
    if (!running_.load()) {
        return;
    }
    
    should_stop_ = true;
    running_ = false;
    
    // Wait for all workers to finish
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

bool ProcessingPipeline::submit_packet(const ParsedPacket& packet) {
    if (!running_.load()) {
        return false;
    }
    
    if (!packet_queue_->push(packet)) {
        packets_dropped_++;
        queue_full_count_++;
        return false;
    }
    
    return true;
}

ProcessingPipeline::PipelineStatistics ProcessingPipeline::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    PipelineStatistics result = stats_;
    result.packets_processed = packets_processed_.load();
    result.packets_dropped = packets_dropped_.load();
    result.queue_full_count = queue_full_count_.load();
    
    // Calculate rates
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_update_).count();
    if (elapsed > 0) {
        result.processing_rate_pps = static_cast<double>(result.packets_processed) / elapsed;
        result.average_processing_time_ms = total_processing_time_.load() / std::max(1.0, static_cast<double>(result.packets_processed));
    }
    
    // Update stage statistics
    result.stage_statistics.clear();
    for (const auto& stage : stages_) {
        PipelineStatistics::StageStats stage_stats;
        stage_stats.name = stage.name;
        stage_stats.packets_processed = stage.packets_processed.load();
        stage_stats.errors = stage.errors.load();
        stage_stats.average_processing_time_ms = stage.total_processing_time.load() / std::max(1.0, static_cast<double>(stage_stats.packets_processed));
        result.stage_statistics.push_back(stage_stats);
    }
    
    return result;
}

size_t ProcessingPipeline::get_queue_depth() const {
    return packet_queue_->size();
}

void ProcessingPipeline::worker_thread(size_t worker_id) {
    auto& batch = worker_batches_[worker_id];
    
    while (running_.load() && !should_stop_.load()) {
        batch.clear();
        
        // Collect packets for batch processing
        ParsedPacket packet;
        size_t batch_count = 0;
        
        while (batch_count < config_.batch_size && 
               packet_queue_->pop(packet) && 
               running_.load() && 
               !should_stop_.load()) {
            batch.push_back(packet);
            batch_count++;
        }
        
        if (!batch.empty()) {
            process_batch(batch);
        } else {
            // No packets available, sleep briefly
            std::this_thread::sleep_for(config_.worker_timeout);
        }
    }
}

void ProcessingPipeline::process_batch(std::vector<ParsedPacket>& batch) {
    auto start_time = std::chrono::steady_clock::now();
    
    for (const auto& packet : batch) {
        // Process through all stages
        for (auto& stage : stages_) {
            try {
                auto stage_start = std::chrono::steady_clock::now();
                stage.function(packet);
                auto stage_end = std::chrono::steady_clock::now();
                
                // Update stage statistics
                stage.packets_processed++;
                auto stage_duration = std::chrono::duration_cast<std::chrono::microseconds>(stage_end - stage_start);
                stage.total_processing_time += stage_duration.count() / 1000.0; // Convert to ms
                
            } catch (const std::exception& e) {
                stage.errors++;
                std::cerr << "Error in stage '" << stage.name << "': " << e.what() << std::endl;
            }
        }
        
        packets_processed_++;
    }
    
    // Update overall statistics
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    total_processing_time_ += duration.count() / 1000.0; // Convert to ms
}

void ProcessingPipeline::update_statistics() {
    // This method can be called periodically to update statistics
    // For now, we'll update them on-demand in get_statistics()
}

} // namespace IntrDet

