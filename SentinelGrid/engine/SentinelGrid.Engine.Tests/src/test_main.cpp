/**
 * @file test_main.cpp
 * @brief This file contains the main entry point for the SentinelGrid Engine Tests application.
 *
 * This application is responsible for running unit tests on various components of the SentinelGrid Engine.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <iostream>

#include <tests/test_framework.hpp>

#include <tests/suites/packet_decoder_tests.hpp>
#include <tests/suites/bounded_queue_tests.hpp>
#include <tests/suites/agent_key_registry_tests.hpp>
#include <tests/suites/authenticated_packet_tests.hpp>
#include <tests/suites/control_plane_encoder_tests.hpp>
#include <tests/suites/failed_login_rules_tests.hpp>
#include <tests/suites/windows_credentials_store_tests.hpp>
#include <tests/suites/shutdown_coordinator_tests.hpp>

/**
 * @brief Main function to run all unit tests.
 *
 * This function serves as the entry point for the test suite. It runs all defined test functions and reports
 * the total number of tests executed and the number of failures. The program exits with a success or failure
 * status based on the test results.
 *
 * @return EXIT_SUCCESS if all tests pass, EXIT_FAILURE otherwise.
 */
int main() {
	namespace tests = sentinelgrid::engine::tests;

	std::cout << "[Test-Suite] SentinelGrid Engine Unit Tests Start\n";

	tests::decode::runTests();
	tests::queue::runTests();
	tests::rules::runTests();
	tests::encoder::runTests();
	tests::registry_key::runTests();
	tests::credential::runTests();
	tests::shutdown::runTests();

	tests::printTestSummary();
	return tests::gFailureCount == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}