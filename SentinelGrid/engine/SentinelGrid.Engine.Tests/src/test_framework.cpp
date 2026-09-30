/*
 * @file test_framework.cpp
 * @brief Implementation of test framework header file.
 *
 * This file contains the implementation of the function to print the tests result summary.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <iostream>

#include <tests/test_framework.hpp>

namespace sentinelgrid::engine::tests {
	std::size_t gTestCount{ 0 };
	std::size_t gFailureCount{ 0 };

	void printTestSummary(void) noexcept {
		std::cout << "\nTest completed: " << gTestCount
			<< " checks, " << gFailureCount << " failures\n";

		if (gFailureCount == 0)
			std::cout << "[PASS] All tests passed.\n";
		else
			std::cout << "[FAIL] Some tests failed.\n";
	}
}