#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

template<typename T>
class BoundedThreadSafeQueue {
private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cond_not_full_;
    std::condition_variable cond_not_empty_;
    size_t max_size_;
    std::atomic<bool> shutdown_ = {false};

public:
    explicit BoundedThreadSafeQueue(size_t max_size) : max_size_(max_size) {}

    void push(T item) {
        if (shutdown_) return;
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;

        queue_.push(std::move(item));
        lock.unlock();
        cond_not_empty_.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        if (shutdown_ && queue_.empty()) return false;

        item = std::move(queue_.front());
        queue_.pop();
        lock.unlock();
        cond_not_full_.notify_one();
        return true;
    }

    void shutdown() {
        shutdown_ = true;
        cond_not_full_.notify_all();
        cond_not_empty_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};
