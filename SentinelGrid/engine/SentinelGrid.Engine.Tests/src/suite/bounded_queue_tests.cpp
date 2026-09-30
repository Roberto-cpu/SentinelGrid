/*
 * @file bounded_queue_tests.cpp
 * @brief Implementation of bounded queue test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <iostream>
#include <chrono>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>

#include <concurrency/bounded_blocking_queue.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/bounded_queue_tests.hpp>

namespace sentinelgrid::engine::tests::queue {
	
	namespace {
		/**
		 * @brief: Tests the FIFO round-trip behavior of the bounded blocking queue.
		 */
		static void testFIFORoundTrip() {
			std::cout << "[+] FIFO queue round-trip...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 3 };

			EXPECT_TRUE(queue.push(10));
			EXPECT_TRUE(queue.push(20));
			EXPECT_TRUE(queue.push(30));


			EXPECT_TRUE(queue.pop() == 10);
			EXPECT_TRUE(queue.pop() == 20);
			EXPECT_TRUE(queue.pop() == 30);
		}

		/**
		 * @brief: Tests the detection of zero capacity initialization.
		 */
		static void testZeroCapacityDetection() {
			std::cout << "[+] Zero Capacity initialization...\n";

			bool exceptionThrown = false;

			try {
				concurrency::BoundedBlockingQueue<int> queue{ 0 };
			}
			catch (const std::invalid_argument&) {
				exceptionThrown = true;
			}

			EXPECT_TRUE(exceptionThrown);
		}

		/**
		 * @brief: Tests the behavior of pushing to a closed queue.
		 */
		static void testPushAfterClose() {
			std::cout << "[+] Push after closing queue...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };
			queue.close();

			EXPECT_TRUE(!queue.push(10));
		}

		/**
		 * @brief: Tests the behavior of draining a closed queue.
		 */
		static void testDrainAfterClose() {
			std::cout << "[+] Drain after close...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 10 };

			EXPECT_TRUE(queue.push(10));
			EXPECT_TRUE(queue.push(20));

			queue.close();
			EXPECT_TRUE(queue.pop() == 10);
			EXPECT_TRUE(queue.pop() == 20);
			EXPECT_TRUE(queue.pop() == std::nullopt);
		}

		/**
		 * @brief: Tests the behavior of a blocked consumer.
		 */
		static void testBlockedConsumer() {
			std::cout << "[+] Blocked consumer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };

			std::promise<void> startedPromise;
			const auto startedFuture = startedPromise.get_future();

			std::promise<std::optional<int>> resultPromise;
			const auto resultFuture = resultPromise.get_future();

			std::jthread consumer{
				[&queue, &startedPromise, &resultPromise]() {
					startedPromise.set_value();
					resultPromise.set_value(queue.pop()); // Blocks the consumer until the a value is pushed into the queue
				}
			};

			startedFuture.wait(); // ensures that the consumer thread has started

			// checks that the consumer waits because the queue is empty
			EXPECT_TRUE(resultFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);
			EXPECT_TRUE(queue.push(42));

			const auto status = resultFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready) {
				const auto result = resultFuture._Get_value();
				EXPECT_TRUE(result.has_value());

				if (result.has_value()) {
					EXPECT_TRUE(result.value() == 42);
				}
			}
		}

		/**
		 * @brief: Tests that closing a queue wakes a blocked consumer.
		 */
		static void testWakesAblockedConsumer() {
			std::cout << "[+] Close wakes a blocked consumer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };

			std::promise<void> startedPromise;
			const auto startedFuture = startedPromise.get_future();

			std::promise<std::optional<int>> resultPromise;
			const auto resultFuture = resultPromise.get_future();

			std::jthread consumer{
				[&queue, &startedPromise, &resultPromise]() {
					startedPromise.set_value();
					resultPromise.set_value(queue.pop()); // Blocks the consumer until the a value is pushed into the queue
				}
			};

			startedFuture.wait(); // ensures that the consumer thread has started

			// checks that the consumer waits because the queue is empty
			EXPECT_TRUE(resultFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);

			queue.close();

			const auto status = resultFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready) {
				const auto result = resultFuture._Get_value();
				EXPECT_TRUE(!result.has_value());
			}
		}

		/**
		 * @brief: Tests the behavior of a full queue blocking a producer.
		 */
		static void testFullQueueBlock() {
			std::cout << "[+] Blocked producer...\n";

			concurrency::BoundedBlockingQueue<int> queue{ 1 };
			EXPECT_TRUE(queue.push(10));

			std::promise<void> startPromise;
			auto startFuture = startPromise.get_future();

			std::promise<std::optional<int>> pushPromise;
			auto pushFuture = pushPromise.get_future();

			std::jthread consumer{
				[&queue, &startPromise, &pushPromise]() {
					startPromise.set_value();
					pushPromise.set_value(queue.push(20));
				}
			};

			startFuture.wait();
			EXPECT_TRUE(pushFuture.wait_for(std::chrono::microseconds{ 50 }) == std::future_status::timeout);

			EXPECT_TRUE(queue.size() == 1);

			const auto first = queue.pop();

			EXPECT_TRUE(first.has_value());

			if (first.has_value()) {
				EXPECT_TRUE(*first == 10);
			}

			const auto status = pushFuture.wait_for(std::chrono::milliseconds{ 1 });
			EXPECT_TRUE(status == std::future_status::ready);

			if (status == std::future_status::ready)
				EXPECT_TRUE(pushFuture.get());

			const auto second = queue.pop();

			EXPECT_TRUE(second.has_value());

			if (second.has_value())
				EXPECT_TRUE(*second == 20);

			queue.close();
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Bounded Queue Tests...\n";

		testFIFORoundTrip();
		testZeroCapacityDetection();
		testPushAfterClose();
		testDrainAfterClose();
		testBlockedConsumer();
		testWakesAblockedConsumer();
		testFullQueueBlock();
	}
}