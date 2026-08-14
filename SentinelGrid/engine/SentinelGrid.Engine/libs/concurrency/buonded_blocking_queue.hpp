#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace sentinelgrid::engine::concurrency {
	
	template<typename T>
	class BoundedBlockingQueue final {
		public:
			
			explicit BoundedBlockingQueue(std::size_t capacity) : capacity_(capacity) {
				if (capacity_ == 0)
					throw std::invalid_argument{"Queue capacity cannot be zero.\n"};
			}

			BoundedBlockingQueue(const BoundedBlockingQueue&) = delete;
			BoundedBlockingQueue& operator=(const BoundedBlockingQueue&) = delete;

			BoundedBlockingQueue(const BoundedBlockingQueue&&) = delete;
			BoundedBlockingQueue& operator=(const BoundedBlockingQueue&&) = delete;
			
			[[nodiscard]]
			bool push(T value) {
				std::unique_lock<std::mutex> lock{ mutex_ };
				notFull_.wait(lock, [this]() { return (closed_ || queue_.size() < capacity_); });

				if (closed_)
					return false;

				queue_.push_back(std::move(value));
				lock.unlock();

				notEmpty_.notify_one();
				return true;
			}

			[[nodiscard]]
			std::optional<T> pop() {
				std::unique_lock<std::mutex> lock{ mutex_ };
				notEmpty_.wait(lock, [this]() { return (closed_ || !queue_.empty()); });

				if (queue_.empty())
					return std::nullopt;

				T item = std::move(queue_.front());
				queue_.pop_front();

				lock.unlock();
				notFull_.notify_one();

				return item;
			}

			void close() {
				{
					std::lock_guard<std::mutex> lock{ mutex_ };
					closed_ = true;
				}

				notEmpty_.notify_all();
				notFull_.notify_all();
			}

			[[nodiscard]]
			bool isClosed() const { 
				std::lock_guard<std::mutex> lock{ mutex_ };
				return closed_; 
			}

			[[nodiscard]]
			std::size_t size() const { 
				std::lock_guard<std::mutex> lock{ mutex_ };
				return queue_.size();
			}

		private:
			std::size_t capacity_;
			std::deque<T> queue_;

			mutable std::mutex mutex_;
			std::condition_variable notEmpty_;
			std::condition_variable notFull_;

			bool closed_{ false };
	};

}