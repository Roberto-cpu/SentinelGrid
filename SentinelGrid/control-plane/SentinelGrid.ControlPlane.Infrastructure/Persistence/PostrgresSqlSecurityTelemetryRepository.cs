using Npgsql;
using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SentinelGrid.ControlPlane.Infrastructure.Persistence;

public sealed class PostrgresSqlSecurityTelemetryRepository : ISecurityTelemetryRepository
{
    private readonly NpgsqlDataSource _dataSource;

    public PostrgresSqlSecurityTelemetryRepository(NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        _dataSource = dataSource;
    }

    public async Task StoreEventAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        string query = """
            INSERT INTO security_events (agent_id, sequence_number, event_type)
            VALUES ($1, $2, $3)
            ON CONFLICT (agent_id, sequence_number) DO NOTHING
            """;

        await using NpgsqlCommand cmd = _dataSource.CreateCommand(query);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint,  (long)securityEvent.AgentId);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Numeric, (decimal)securityEvent.SequenceNumber);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Integer, (int)securityEvent.Type);

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task StoreAlertAsync(SecurityAlert securityAlert, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityAlert);
        cancellationToken.ThrowIfCancellationRequested();

        string query = """
            INSERT INTO security_alert (alert_type, severity, agent_id, triggering_sequence, failure_count)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (alert_type, agent_id, triggering_sequence) DO NOTHING
            """;

        await using NpgsqlCommand cmd = _dataSource.CreateCommand(query);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Integer, (int)securityAlert.Type);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Integer, (int)securityAlert.Severity);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint,  (long)securityAlert.AgentId);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Numeric, (decimal)securityAlert.SequenceNumber);
        cmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint,  (long)securityAlert.FailureCounts);

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }
}
