using Microsoft.Extensions.Configuration;
using Npgsql;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Infrastructure.Persistence;
using static SentinelGrid.ControlPane.Tests.DecoderTests;

namespace SentinelGrid.ControlPlane.Tests;

[TestClass]
public sealed class PostgreSqlSecurityTelemetryRepositoryTests
{
    private const uint TestAgentId = 900001U;
    private const ulong TestSequenceNumber = 700001UL;

    private static NpgsqlDataSource _dataSource = null!;
    private static PostrgresSqlSecurityTelemetryRepository _repository = null!;

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
