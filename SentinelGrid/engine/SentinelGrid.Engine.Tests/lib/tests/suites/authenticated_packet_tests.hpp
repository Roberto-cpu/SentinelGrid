#pragma once

/*
 * @file test_framework.hpp
 * @brief Test framework to define the expected test result logic
 *
 * This file contains the expected true condition to pass unit tests.
 * Also contains a function to print test summary.
 *
 * @note The implementation of the printSummary function is expected to be
 * provided in a correspoding source file (e.g., test_framework.cpp)
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <iostream>
#include <cstdio>
#include <cstddef>

static int gTestCount = 0;
static int gFailureCount = 0;

#define EXPECT_TRUE(condition)				\
	do {									\
		gTestCount++;						\
		if (!(condition)) {					\
			gFailureCount++;					\
			printf(							\
				"[FAIL] Line %d: %s\n",		\
				__LINE__,					\
				#condition					\
			);								\
		}									\
	} while(0)								\

namespace sentinelgrid::engine::tests {

	/**
	 * @brief Prints the overall tests results
	 */
	[[nodiscard]]
	void printTestSummary(void) noexcept;
}