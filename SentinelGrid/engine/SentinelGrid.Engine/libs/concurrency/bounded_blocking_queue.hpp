#pragma once

/**
 * @file bounded_blocking_queue.hpp
 * @brief This header file defines a thread-safe bounded blocking queue.
 *
 * The BoundedBlockingQueue class provides a thread-safe queue with a fixed capacity that blocks
 * when trying to push to a full queue or pop from an empty queue. It is designed for use in
 * concurrent programming scenarios where multiple threads need to communicate through a shared queue.
 *
 * @note The implementation of the BoundedBlockingQueue class is provided in this header file.
 *
 * @tparam T The type of elements stored in the queue.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace sentinelgrid::engine::concurrency {
	
	/**
	 * @class BoundedBlockingQueue
	 * @brief A thread-safe bounded blocking queue.
	 *
	 * The BoundedBlockingQueue class provides a thread-safe queue with a fixed capacity that blocks
	 * when trying to push to a full queue or pop from an empty queue. It is designed for use in
	 * concurrent programming scenarios where multiple threads need to communicate through a shared queue.
	 *
	 * @tparam T The type of elements stored in the queue.
	 */
	template<typename T>
	class BoundedBlockingQueue final {
		public:
			
			/**
			 * @brief Constructs a new BoundedBlockingQueue object with the specified capacity.
			 * @param capacity The maximum number of elements that can be stored in the queue.
			 * @throws std::invalid_argument if the capacity is zero.
			 */
			explicit BoundedBlockingQueue(std::size_t capacity) : capacity_(capacity) {
				if (capacity_ == 0)
					throw std::invalid_argument{"Queue capacity cannot be zero.\n"};
			}

			/**
			 * @brief Destroys the BoundedBlockingQueue object and closes the queue.
			 */
			BoundedBlockingQueue(const BoundedBlockingQueue&) = delete;
			
			/**
			 * @brief Deleted copy assignment operator to prevent copying of BoundedBlockingQueue instances.
			 */
			BoundedBlockingQueue& operator=(const BoundedBlockingQueue&) = delete;

			/**
			 * @brief Deleted move constructor to prevent moving of BoundedBlockingQueue instances.
			 */
			BoundedBlockingQueue(const BoundedBlockingQueue&&) = delete;
			
			/**
			 * @brief Deleted move assignment operator to prevent moving of BoundedBlockingQueue instances.
			 */
			BoundedBlockingQueue& operator=(const BoundedBlockingQueue&&) = delete;
			
			/**
			 * @brief Pushes an element into the queue. Blocks if the queue is full.
			 * @param value The element to push into the queue.
			 * @return true if the element was successfully pushed, false if the queue is closed.
			 */
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

			/**
			 * @brief Pops an element from the queue. Blocks if the queue is empty.
			 * @return An optional containing the popped element, or std::nullopt if the queue is closed and empty.
			 */
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

			/**
			 * @brief Closes the queue, unblocking any waiting threads.
			 *
			 * After calling this method, any subsequent calls to push() will return false,
			 * and pop() will return std::nullopt if the queue is empty.
			 */
			void close() {
				{
					std::lock_guard<std::mutex> lock{ mutex_ };
					closed_ = true;
				}

				notEmpty_.notify_all();
				notFull_.notify_all();
			}

			/**
			 * @brief Checks if the queue is closed.
			 * @return true if the queue is closed, false otherwise.
			 */
			[[nodiscard]]
			bool isClosed() const { 
				std::lock_guard<std::mutex> lock{ mutex_ };
				return closed_; 
			}

			/**
			 * @brief Returns the current size of the queue.
			 * @return The number of elements currently in the queue.
			 */
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