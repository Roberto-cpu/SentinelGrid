#pragma once

/*
 * @file test_framework.h
 * @brief Test framework to define the expected test result logic
 * 
 * This file contains the expected true condition to pass unit tests. 
 * Also contains a function to print test summary.
 * 
 * @note The implementation of the printSummary function is expected to be 
 * provided in a correspoding source file (e.g., test_framework.c) 
 * 
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include <stddef.h>
#include <stdio.h>

extern size_t g_testCount;
extern size_t g_failureCount;

/*
 * @brief Test condition analysis
 * 
 * Defines the logic to check if a test pass or not, 
 * starting by the given condition
 */
#define EXPECT_TRUE(condition)				\
	do {									\
		g_testCount++;						\
		if (!(condition)) {					\
			g_failureCount++;					\
			printf(							\
				"[FAIL] Line %d: %s\n",		\
				__LINE__,					\
				#condition					\
			);								\
		}									\
	} while(0)								\

/*
 * @brief Prints the unit tests result summary
 */
void printTestSummary(void);