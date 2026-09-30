#pragma once

/*
 * @file shutdown_coordinator_tests.hpp
 * @brief Defines the runner for the shutdown request handling related tests
 *
 * This file defines the runner function that contains all the shutdown requests
 * handling related testing function.
 *
 * @note The implementation of the runTests function is expected to be
 * provided in a correspoding source file (e.g. shutdown_coordinator_tests.cpp)
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

namespace sentinelgrid::engine::tests::shutdown {

	/**
	 * @brief Executes all the contained tests
	 */
	void runTests();
}