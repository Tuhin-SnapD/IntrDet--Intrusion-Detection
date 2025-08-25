#pragma once

// Mock Boost headers for testing purposes
// This allows compilation without the actual Boost library

#include <chrono>
#include <thread>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <string>
#include <iostream>

// Mock boost::system namespace
namespace boost {
namespace system {

class error_code {
public:
    error_code() : value_(0) {}
    explicit error_code(int val) : value_(val) {}
    
    int value() const { return value_; }
    bool operator!() const { return value_ == 0; }
    operator bool() const { return value_ != 0; }
    
private:
    int value_;
};

class error_category {
public:
    virtual ~error_category() = default;
    virtual const char* name() const noexcept = 0;
    virtual std::string message(int ev) const = 0;
};

class system_category : public error_category {
public:
    const char* name() const noexcept override { return "system"; }
    std::string message(int ev) const override { (void)ev; return "system error"; }
};

} // namespace system
} // namespace boost

// Mock boost::asio namespace
namespace boost {
namespace asio {

class io_context {
public:
    io_context() = default;
    ~io_context() = default;
    
    void run() {
        // Mock implementation - just sleep
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    void stop() {
        // Mock implementation
    }
    
    template<typename CompletionHandler>
    void post(CompletionHandler&& handler) {
        // Mock implementation - just call the handler
        handler();
    }
    
    template<typename CompletionHandler>
    void dispatch(CompletionHandler&& handler) {
        // Mock implementation - just call the handler
        handler();
    }
    
    class work {
    public:
        explicit work(io_context& ctx) : context_(ctx) {}
        ~work() = default;
        
    private:
        io_context& context_;
    };
    
    class executor_type {
    public:
        executor_type() = default;
        ~executor_type() = default;
        
        template<typename CompletionHandler>
        void post(CompletionHandler&& handler) {
            // Mock implementation
            handler();
        }
        
        template<typename CompletionHandler>
        void dispatch(CompletionHandler&& handler) {
            // Mock implementation
            handler();
        }
    };
    
    executor_type get_executor() {
        return executor_type{};
    }
};

// Mock boost::asio::ip namespace
namespace ip {

class address {
public:
    address() = default;
    ~address() = default;
    
    static address from_string(const std::string& addr) {
        (void)addr; // Suppress unused parameter warning
        return address{};
    }
    
    std::string to_string() const {
        return "127.0.0.1"; // Mock implementation
    }
};

class tcp {
public:
    class endpoint {
    public:
        endpoint() = default;
        endpoint(const std::string& address, uint16_t port) : address_(address), port_(port) {}
        endpoint(const boost::asio::ip::address& address, uint16_t port) : address_(address.to_string()), port_(port) {}
        
        std::string address() const { return address_; }
        uint16_t port() const { return port_; }
        
    private:
        std::string address_;
        uint16_t port_;
    };
    
    class acceptor {
    public:
        acceptor(boost::asio::io_context& io_context, const endpoint& ep) : io_context_(io_context), endpoint_(ep) {}
        ~acceptor() = default;
        
        void listen() {
            // Mock implementation
        }
        
        template<typename AcceptHandler>
        void async_accept(AcceptHandler&& handler) {
            // Mock implementation
            handler(boost::system::error_code{}, boost::asio::ip::tcp::socket{io_context_});
        }
        
    private:
        boost::asio::io_context& io_context_;
        endpoint endpoint_;
    };
    
    class socket {
    public:
        socket(boost::asio::io_context& io_context) : io_context_(io_context) {}
        ~socket() = default;
        
    private:
        boost::asio::io_context& io_context_;
    };
};

} // namespace ip

} // namespace asio

// Mock boost::thread namespace
namespace thread {

class thread {
public:
    thread() = default;
    
    template<typename Callable>
    explicit thread(Callable&& f) {
        // Mock implementation - just call the function
        f();
    }
    
    ~thread() = default;
    
    void join() {
        // Mock implementation
    }
    
    void detach() {
        // Mock implementation
    }
    
    bool joinable() const {
        return false; // Mock implementation
    }
};

} // namespace thread

// Mock boost::lockfree namespace
namespace lockfree {

template<typename T, size_t Size>
class queue {
public:
    queue() = default;
    ~queue() = default;
    
    bool push(const T& item) {
        if (queue_.size() < Size) {
            queue_.push(item);
            return true;
        }
        return false;
    }
    
    bool pop(T& item) {
        if (!queue_.empty()) {
            item = queue_.front();
            queue_.pop();
            return true;
        }
        return false;
    }
    
    bool empty() const {
        return queue_.empty();
    }
    
    size_t size() const {
        return queue_.size();
    }
    
private:
    std::queue<T> queue_;
};

} // namespace lockfree

// Mock boost::optional
template<typename T>
class optional {
public:
    optional() : has_value_(false) {}
    explicit optional(const T& value) : value_(value), has_value_(true) {}
    
    bool has_value() const { return has_value_; }
    const T& value() const { return value_; }
    T& value() { return value_; }
    
    const T& operator*() const { return value_; }
    T& operator*() { return value_; }
    
    const T* operator->() const { return &value_; }
    T* operator->() { return &value_; }
    
    operator bool() const { return has_value_; }
    
private:
    T value_;
    bool has_value_;
};

} // namespace boost

// Global function for system_category
inline const boost::system::system_category& system_category() {
    static boost::system::system_category instance;
    return instance;
}
