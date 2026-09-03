#pragma once

/**
 * @file unique_socket.hpp
 * @brief This header file defines the UniqueSocket class, which provides a RAII wrapper for managing a Windows socket handle.
 *
 * The UniqueSocket class ensures that the socket handle is properly closed when the object goes out of scope, preventing resource leaks.
 *
 * @note The implementation of the UniqueSocket class is expected to be provided in a corresponding source file (e.g., unique_socket.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <WinSock2.h>

namespace sentinelgrid::engine::network {

	/**
	 * @class UniqueSocket
	 * @brief A RAII wrapper for managing a Windows socket handle.
	 *
	 * The UniqueSocket class ensures that the socket handle is properly closed when the object goes out of scope, preventing resource leaks.
	 */
	class UniqueSocket final {

		public:
			/**
			 * @brief Constructs a new UniqueSocket object with an invalid socket handle.
			 */
			UniqueSocket() noexcept = default;
			
			/**
			 * @brief Constructs a new UniqueSocket object with the specified socket handle.
			 * @param handler The socket handle to manage.
			 */
			explicit UniqueSocket(SOCKET handler) noexcept;

			/**
			 * @brief Destroys the UniqueSocket object and closes the socket handle if it is valid.
			 */
			~UniqueSocket() noexcept;

			/**
			 * @brief Deleted copy constructor to prevent copying of UniqueSocket instances.
			 */
			UniqueSocket(const UniqueSocket&) = delete;
			
			/**
			 * @brief Deleted copy assignment operator to prevent copying of UniqueSocket instances.
			 */
			UniqueSocket& operator = (const UniqueSocket&) = delete;

			/**
			 * @brief Move constructor to transfer ownership of the socket handle from another UniqueSocket instance.
			 * @param other The UniqueSocket instance to move from.
			 */
			UniqueSocket(UniqueSocket&& other) noexcept;
			
			/**
			 * @brief Move assignment operator to transfer ownership of the socket handle from another UniqueSocket instance.
			 * @param other The UniqueSocket instance to move from.
			 * @return A reference to the current UniqueSocket instance.
			 */
			UniqueSocket& operator=(UniqueSocket&& other) noexcept;

			/**
			 * @brief Checks if the socket handle is valid.
			 * @return true if the socket handle is valid, false otherwise.
			 */
			[[nodiscard]]
			bool isValid() const noexcept;

			/**
			 * @brief Retrieves the underlying socket handle.
			 * @return The socket handle.
			 */
			[[nodiscard]]
			SOCKET get() const noexcept;

			/**
			 * @brief Releases ownership of the socket handle and returns it.
			 * @return The socket handle that was managed by this UniqueSocket instance.
			 */
			[[nodiscard]]
			SOCKET release() noexcept;

			/**
			 * @brief Resets the UniqueSocket instance to manage a new socket handle, closing the previous handle if it was valid.
			 * @param newHandle The new socket handle to manage. Defaults to INVALID_SOCKET.
			 */
			[[nodiscard]]
			void reset(SOCKET newHandle = INVALID_SOCKET) noexcept;

		private:
			SOCKET handler_{ INVALID_SOCKET };
	};
}