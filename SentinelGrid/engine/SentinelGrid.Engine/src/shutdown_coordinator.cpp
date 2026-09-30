/**
 * @file shutdown_coordinator.cpp
 * @brief Contains the implementation of shutdown requests handling class
 * 
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <stop_token>

#include <concurrency/shutdown_coordinator.hpp>

namespace sentinelgrid::engine::concurrency {

	std::stop_token ShutdownCoordinator::token() const noexcept { return stopSrc_.get_token(); }

	bool ShutdownCoordinator::stopRequested() const noexcept { return stopSrc_.stop_requested(); }

	bool ShutdownCoordinator::requestStop() noexcept {
		if (stopRequested()) return false;

		return stopSrc_.request_stop();
	}
}