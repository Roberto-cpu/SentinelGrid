/*
 * @file test_framework.c
 * @brief Implementation of test framework header file.
 * 
 * This file contains the implementation of the function to print the tests result summary.
 * 
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include  <test_framework.h>

size_t g_testCount	= 0U;
size_t g_failureCount = 0U;

void printTestSummary(void) {
	printf(
		"\nTest completed: %zu checks, %zu failures\n",
		g_testCount,
		g_failureCount
	);

	if (g_failureCount == 0)
		printf("[PASS] All tests passed.\n");
	else
		printf("[FAIL] Some tests failed.\n");
}