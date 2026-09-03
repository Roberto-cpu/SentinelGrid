/**
 * @file PostgreSqlSecurityTelemetryRepositoryTests.cs
 * @brief Contains unit tests for the PostrgresSqlSecurityTelemetryRepository class.
 * 
 * This file includes tests that verify the functionality of storing and retrieving security events and alerts
 * in a PostgreSQL database using the PostrgresSqlSecurityTelemetryRepository class. The tests cover scenarios
 * such as storing events, storing alerts, handling cancellation tokens, and ensuring data integrity.
 * 
 * @note These tests require a valid PostgreSQL connection string to be provided via user secrets.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using Microsoft.Extensions.Configuration;
using Npgsql;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Infrastructure.Persistence;
using static SentinelGrid.ControlPane.Tests.DecoderTests;

namespace SentinelGrid.ControlPlane.Tests;

/**
 * @class PostgreSqlSecurityTelemetryRepositoryTests
 * @brief Unit tests for the PostrgresSqlSecurityTelemetryRepository class.
 *
 * This test class contains unit tests that verify the functionality of the PostrgresSqlSecurityTelemetryRepository class,
 * which is responsible for storing and retrieving security events and alerts in a PostgreSQL database. The tests cover
 * various scenarios, including storing events, storing alerts, handling cancellation tokens, and ensuring data integrity.
 */
[TestClass]
public sealed class PostgreSqlSecurityTelemetryRepositoryTests
{
    private const uint TestAgentId = 900001U;
    private const ulong TestSequenceNumber = 700001UL;

    private static NpgsqlDataSource _dataSource = null!;
    private static PostrgresSqlSecurityTelemetryRepository _repository = null!;

    /**
     * @brief Initializes the test class by setting up the PostgreSQL data source and repository.
     * @param context The test context provided by the testing framework.
     *
     * This method is called once before any tests are run. It retrieves the PostgreSQL connection string from user secrets,
     * creates an NpgsqlDataSource, and initializes the PostrgresSqlSecurityTelemetryRepository for use in the tests.
     */
    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        IConfiguration configuration = new ConfigurationBuilder()
                    .AddUserSecrets<PostgreSqlConnectionTests>(optional: false)
                    .Build();

        string connectionString = configuration.GetConnectionString("SentinelGrid")
            ?? throw new InvalidOperationException("Test connection string is missing.");

        _dataSource = NpgsqlDataSource.Create(connectionString);
        _repository = new PostrgresSqlSecurityTelemetryRepository(_dataSource);
    }

    /**
     * @brief Cleans up the test class by disposing of the PostgreSQL data source.
     *
     * This method is called once after all tests have been run. It disposes of the NpgsqlDataSource to release any
     * resources associated with the PostgreSQL connection.
     */
    private async Task<long> CountAlertAsync(AlertTypes type, uint agentId, ulong sequence)
    {
        const string query = """
            SELECT COUNT(*) 
            FROM security_alerts
            WHERE alert_type = $1
                AND agent_id = $2
                AND triggering_sequence = $3
            """;

        await using NpgsqlCommand command = _dataSource.CreateCommand(query);
        command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Integer, (int)type);
        command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint, (long)agentId);
        command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Numeric, (decimal)sequence);

        Object? result = await command.ExecuteScalarAsync();
        Assert.IsNotNull(result);

        return Convert.ToInt64(result);
    }

    /**
     * @brief Counts the number of security events in the database for a given agent ID and sequence number.
     * @param agentId The agent ID to filter the events.
     * @param sequence The sequence number to filter the events.
     * @returns The count of security events matching the specified criteria.
     *
     * This method executes a SQL query to count the number of security events in the database that match the provided
     * agent ID and sequence number. It returns the count as a long integer.
     */
    private async Task<long> CountEventAsync(uint agentId, ulong sequence)
    {
        const string query = """
            SELECT COUNT(*) 
            FROM security_events
            WHERE agent_id = $1
                AND sequence_number = $2
            """;

        await using NpgsqlCommand command = _dataSource.CreateCommand(query);
        command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint, (long)agentId);
        command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Numeric, (decimal)sequence);

        Object? result = await command.ExecuteScalarAsync();
        Assert.IsNotNull(result);

        return Convert.ToInt64(result);
    }

    /**
     * @brief Tests the storage of a SecurityEvent in the PostgreSQL repository.
     *
     * This test verifies that a SecurityEvent can be successfully stored in the PostgreSQL database using the
     * PostrgresSqlSecurityTelemetryRepository. It checks that the event is stored correctly and can be retrieved
     * by counting the number of events with the specified agent ID and sequence number.
     */
    [TestMethod]
    public async Task StoreAlertAsync_WhenEventExists_StoreAlert()
    {
        SecurityEvent securityEvent = new(
            TestAgentId,
            TestSequenceNumber,
            EventTypes.LoginFailed
        );

        SecurityAlert securityAlert = new(
            AlertTypes.RepeatedLoginFailures,
            AlertSeverities.High,
            TestAgentId,
            TestSequenceNumber,
            3U
        );

        await _repository.StoreEventAsync( securityEvent, CancellationToken.None );
        await _repository.StoreAlertAsync( securityAlert, CancellationToken.None );
        await _repository.StoreAlertAsync( securityAlert, CancellationToken.None );

        long count = await CountAlertAsync(securityAlert.Type, securityAlert.AgentId, securityAlert.SequenceNumber);
        Assert.AreEqual(1L, count);
    }

    /**
     * @brief Tests the storage of a SecurityEvent with two valid SecurityAlerts in the PostgreSQL repository.
     *
     * This test verifies that a SecurityEvent can be successfully stored along with two valid SecurityAlerts in the
     * PostgreSQL database using the PostrgresSqlSecurityTelemetryRepository. It checks that the event and alerts are
     * stored correctly and can be retrieved by counting the number of events and alerts with the specified criteria.
     */
    [TestMethod]
    public async Task TestEventStore_WithTwoValidAlertStore_StoreAnalysis()
    {
        uint agentId = TestAgentId + 1;
        ulong sequence = TestSequenceNumber + 1;

        SecurityEvent securityEvent = new(
            agentId,
            sequence,
            EventTypes.LoginFailed
        );

        IReadOnlyCollection<SecurityAlert> alerts = [
            new SecurityAlert(AlertTypes.RepeatedLoginFailures, AlertSeverities.High, agentId, sequence, 3U),
            new SecurityAlert(AlertTypes.MaliciousRequest, AlertSeverities.Critical, agentId, sequence, 1U)
        ];

        await _repository.StoreAnalysisResultAsync(securityEvent, alerts, CancellationToken.None);

        long eventCnt = await CountEventAsync(agentId, sequence);
        long alertCnt = await CountAlertAsync(AlertTypes.RepeatedLoginFailures, agentId, sequence) + await CountAlertAsync(AlertTypes.MaliciousRequest, agentId, sequence);

        Assert.AreEqual(1L, eventCnt);
        Assert.AreEqual(2L, alertCnt);
    }

    /**
     * @brief Tests the storage of a SecurityEvent without any SecurityAlerts in the PostgreSQL repository.
     *
     * This test verifies that a SecurityEvent can be successfully stored in the PostgreSQL database using the
     * PostrgresSqlSecurityTelemetryRepository without any associated SecurityAlerts. It checks that the event is
     * stored correctly and can be retrieved by counting the number of events with the specified agent ID and sequence number.
     */
    [TestMethod]
    public async Task TestEventStore_WithoutAlerts_StoreAnalysis()
    {
        uint agentId = TestAgentId + 2;
        ulong sequence = TestSequenceNumber + 1;

        SecurityEvent securityEvent = new(
            agentId,
            sequence,
            EventTypes.LoginFailed
        );

        IReadOnlyCollection<SecurityAlert> alerts = [];

        await _repository.StoreAnalysisResultAsync(securityEvent, alerts, CancellationToken.None);

        long eventCnt = await CountEventAsync(agentId, sequence);
        
        Assert.AreEqual(1L, eventCnt);
    }

    /**
      * @brief Tests the storage of a SecurityEvent with an invalid SecurityAlert in the PostgreSQL repository.
      *
      * This test verifies that a SecurityEvent can be successfully stored in the PostgreSQL database using the
      * PostrgresSqlSecurityTelemetryRepository, even when one of the associated SecurityAlerts is invalid (e.g., has a different agent ID).
      * It checks that neither the event nor the alerts are stored, ensuring data integrity.
      */
    [TestMethod]
    public async Task TestEventStore_WithInvalidAlert_StoreAnalysis()
    {
        uint agentId = TestAgentId + 3;
        ulong sequence = TestSequenceNumber + 1;

        SecurityEvent securityEvent = new(
            agentId,
            sequence,
            EventTypes.LoginFailed
        );

        IReadOnlyCollection<SecurityAlert> alerts = [
            new SecurityAlert(AlertTypes.RepeatedLoginFailures, AlertSeverities.High, agentId, sequence, 3U),
            new SecurityAlert(AlertTypes.MaliciousRequest, AlertSeverities.Critical, agentId + 1, sequence + 1, 1U)
        ];

        await _repository.StoreAnalysisResultAsync(securityEvent, alerts, CancellationToken.None);

        long eventCnt = await CountEventAsync(agentId, sequence);
        long alertCnt = await CountAlertAsync(AlertTypes.RepeatedLoginFailures, agentId, sequence) + await CountAlertAsync(AlertTypes.MaliciousRequest, agentId + 1, sequence + 1);

        Assert.AreEqual(0L, eventCnt);
        Assert.AreEqual(0L, alertCnt);
    }

    /**
     * @brief Tests the behavior of the PostgreSQL repository when a cancellation token is triggered.
     *
     * This test verifies that the PostrgresSqlSecurityTelemetryRepository correctly handles a cancellation token
     * by throwing an OperationCanceledException when attempting to store a SecurityEvent and associated SecurityAlerts.
     * It ensures that the repository respects cancellation requests and does not perform any database operations when canceled.
     */
    [TestMethod]
    public async Task TestEventAlertStore_WithCancelledToken_StoreAnalysis()
    {
        uint agentId = TestAgentId + 4;
        ulong sequence = TestSequenceNumber + 1;

        SecurityEvent securityEvent = new(
            agentId,
            sequence,
            EventTypes.LoginFailed
        );

        IReadOnlyCollection<SecurityAlert> alerts = [
            new SecurityAlert(AlertTypes.RepeatedLoginFailures, AlertSeverities.High, agentId, sequence, 3U),
            new SecurityAlert(AlertTypes.MaliciousRequest, AlertSeverities.Critical, agentId, sequence, 1U)
        ];

        CancellationTokenSource tokenSource = new CancellationTokenSource();
        tokenSource.Cancel();

        bool exception = false;

        try {
            await _repository.StoreAnalysisResultAsync(securityEvent, alerts, tokenSource.Token);
        }
        catch (OperationCanceledException)
        {
            exception = true;
        }

        Assert.IsTrue(exception);
    }
}
