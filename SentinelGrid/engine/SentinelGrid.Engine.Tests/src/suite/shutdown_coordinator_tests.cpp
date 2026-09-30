/**
 * @file shutdown_coordinator_tests.cpp
 * @brief Implementation of shutdown requests handling test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <iostream>
#include <stop_token>
#include <type_traits>

#include <concurrency/shutdown_coordinator.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/shutdown_coordinator_tests.hpp>

namespace sentinelgrid::engine::tests::shutdown {

	namespace {

		static_assert(
			!std::is_copy_constructible_v<
			engine::concurrency::ShutdownCoordinator>);

		static_assert(
			!std::is_copy_assignable_v<
			engine::concurrency::ShutdownCoordinator>);

		static_assert(
			!std::is_move_constructible_v<
			engine::concurrency::ShutdownCoordinator>);

		static_assert(
			!std::is_move_assignable_v<
			engine::concurrency::ShutdownCoordinator>);

		/**
		 * @brief Checks that a new ShutdownCoordinator instance not
		 *		starts in stopped state
		 */
		static void testShutdownCoordinatorInitiallyRunning() {
			std::cout << "[+] Initial state test...\n";

			engine::concurrency::ShutdownCoordinator coordinator;
			std::stop_token token =  coordinator.token();

			EXPECT_TRUE(!coordinator.stopRequested());
			EXPECT_TRUE(!token.stop_requested());
			EXPECT_TRUE(token.stop_possible());
		}

		/**
		 * @brief Checks that the coordinator is able to manage two or
		 *		more stop requests 
		 */
		static void testShutdownCoordinatorBroadcastStop() {
			std::cout << "[+] More stop requests management test...\n";

			engine::concurrency::ShutdownCoordinator coordinator;

			std::stop_token tokenOne = coordinator.token();
			std::stop_token tokenTwo = coordinator.token();

			const bool requestRes = coordinator.requestStop();
			EXPECT_TRUE(requestRes);

			if (!requestRes) return;
			
			EXPECT_TRUE(coordinator.stopRequested());
			EXPECT_TRUE(tokenOne.stop_requested());
			EXPECT_TRUE(tokenTwo.stop_requested());
		}

		/**
		 * @brief Checks that a stop request is idempotent
		 */
		static void testShutdownCoordinatorRequestIsIdempotent() {
			std::cout << "[+] Idempotent stop requests...\n";

			engine::concurrency::ShutdownCoordinator coordinator;

			std::stop_token token = coordinator.token();

			const bool requestResOne = coordinator.requestStop();
			const bool requestResTwo = coordinator.requestStop();
			
			EXPECT_TRUE(requestResOne);
			EXPECT_TRUE(!requestResTwo);

			EXPECT_TRUE(coordinator.stopRequested());
			EXPECT_TRUE(token.stop_requested());
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Shutdown Requests Handling Tests...\n";

		testShutdownCoordinatorInitiallyRunning();
		testShutdownCoordinatorBroadcastStop();
		testShutdownCoordinatorRequestIsIdempotent();
	}
}