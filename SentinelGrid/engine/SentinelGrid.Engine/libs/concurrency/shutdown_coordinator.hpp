#pragma once

/**
 * @file shutdown_coordinator.hpp
 * @brief This header file defines the shutdown request management functions
 * 
 * The ShutdownCoordinator class provides the functions to safely and correctly handle
 * engine shutdown requests. The stop_token library allwos to handle thread-safe request
 * queue
 * 
 * @note The implementation of the ShutdownCoordinator class' functions is provided into
 *		a related coding file (e.g. shutdown_coordinator.cpp)
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <stop_token>

namespace sentinelgrid::engine::concurrency {

	class ShutdownCoordinator final {
	public:
		/**
		 * @brief public constructor
		 * 
		 * It constructs a new ShutdownCoordinator instance
		 */
		ShutdownCoordinator() = default;

		/**
		 * @brief Destroys the ShutdownCoordinator object
		 */
		ShutdownCoordinator(const ShutdownCoordinator&) = delete;
		
		/**
		 * @brief Deleted copy assignment operator to prevent copying of ShutdownCoordinator instances.
		 */
		ShutdownCoordinator& operator=(const ShutdownCoordinator&) = delete;

		/**
		 * @brief Deleted move constructor to prevent moving of ShutdownCoordinator instances.
		 */
		ShutdownCoordinator(const ShutdownCoordinator&&) = delete;

		/**
		 * @brief Deleted move assignment operator to prevent moving of ShutdownCoordinator instances.
		 */
		ShutdownCoordinator& operator=(const ShutdownCoordinator&&) = delete;

		/**
		 * @brief Retrieves the request token from the stopSrc_
		 * 
		 * @returns the retrieved stop_token
		 */
		[[nodiscard]]
		std::stop_token token() const noexcept;

		/**
		 * @brief Indicates if a shutdown request has been already handled
		 * 
		 * @returns True if a request is already sent; False otherwise
		 */
		[[nodiscard]]
		bool stopRequested() const noexcept;

		/**
		 * @brief Handles the shutdown requests 
		 * 
		 * @returns True for the first successfull request; False otherwise
		 */
		bool requestStop() noexcept;

	private:
		std::stop_source stopSrc_;
	};
}