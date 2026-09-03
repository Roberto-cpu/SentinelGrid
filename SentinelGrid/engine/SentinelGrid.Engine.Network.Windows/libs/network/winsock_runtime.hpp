#pragma once
/**
 * @file winsock_runtime.hpp
 * @brief Declaration of the WinsockRuntime class for managing the Winsock library initialization and cleanup.
 * 
 * This file contains the declaration of the WinsockRuntime class, which is responsible for initializing and cleaning up the Winsock library in a Windows environment.
 * 
 * @note The implementation of the WinsockRuntime class is expected to be provided in a corresponding source file (e.g., winsock_runtime.cpp).
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace sentinelgrid::engine::network {

	/**
	 * @brief Manages the initialization and cleanup of the Winsock library.
	 */
	class WinsockRuntime final {
		public:
			/**
			 * @brief Constructs a new WinsockRuntime object and initializes the Winsock library.
			 */
			WinsockRuntime() noexcept;
			
			/**
			 * @brief Destroys the WinsockRuntime object and cleans up the Winsock library.
			 */
			~WinsockRuntime() noexcept;

			/**
			 * @brief Deleted copy constructor to prevent copying of WinsockRuntime instances.
			 */
			WinsockRuntime(const WinsockRuntime&) = delete;
			
			/**
			 * @brief Deleted copy assignment operator to prevent copying of WinsockRuntime instances.
			 */
			WinsockRuntime& operator = (const WinsockRuntime&&) = delete;

			/**
			 * @brief Deleted move constructor to prevent moving of WinsockRuntime instances.
			 */
			[[nodiscard]]
			bool isReady() const noexcept;

			/**
			 * @brief Deleted move assignment operator to prevent moving of WinsockRuntime instances.
			 */
			[[nodiscard]]
			int errorCode() const noexcept;

		private:
			bool initialized_{ false };
			int errCode_{ 0 };
	};
}