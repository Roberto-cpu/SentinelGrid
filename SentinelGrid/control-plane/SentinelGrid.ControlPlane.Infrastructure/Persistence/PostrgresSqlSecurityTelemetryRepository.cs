using Microsoft.Extensions.Logging;
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
            INSERT INTO security_alerts (alert_type, severity, agent_id, triggering_sequence, failure_count)
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

    public async Task StoreAnalysisResultAsync(
        SecurityEvent securityEvent, IReadOnlyCollection<SecurityAlert> alerts, 
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        ArgumentNullException.ThrowIfNull(alerts);
        cancellationToken.ThrowIfCancellationRequested();

        const string insertEvent = """
            INSERT INTO security_events (agent_id, sequence_number, event_type)
            VALUES ($1, $2, $3)
            ON CONFLICT (agent_id, sequence_number) DO NOTHING
            """;

        const string insertAlert = """
            INSERT INTO security_alerts (alert_type, severity, agent_id, triggering_sequence, failure_count)
            VALUES (@alert_type, @alert_severity, @agent_id, @triggering_sequence, @failure_count)
            ON CONFLICT (alert_type, agent_id, triggering_sequence) DO NOTHING
            """;

        await using var connection = await _dataSource.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (NpgsqlCommand eventCmd = new(insertEvent, connection, transaction)) 
        {
            eventCmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Bigint, (long)securityEvent.AgentId);
            eventCmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Numeric, (decimal)securityEvent.SequenceNumber);
            eventCmd.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Integer, (int)securityEvent.Type);

            await eventCmd.ExecuteNonQueryAsync();
        }

        await using (NpgsqlCommand alertCmd = new(insertAlert, connection, transaction))
        {
            alertCmd.Parameters.Add(new NpgsqlParameter("alert_type", NpgsqlTypes.NpgsqlDbType.Integer));
            alertCmd.Parameters.Add(new NpgsqlParameter("alert_severity", NpgsqlTypes.NpgsqlDbType.Integer));
            alertCmd.Parameters.Add(new NpgsqlParameter("agent_id", NpgsqlTypes.NpgsqlDbType.Bigint));
            alertCmd.Parameters.Add(new NpgsqlParameter("triggering_sequence", NpgsqlTypes.NpgsqlDbType.Numeric));
            alertCmd.Parameters.Add(new NpgsqlParameter("failure_count", NpgsqlTypes.NpgsqlDbType.Bigint));

            foreach (var alert in alerts)
            {
                alertCmd.Parameters["alert_type"].Value = (int)alert.Type;
                alertCmd.Parameters["alert_severity"].Value = (int)alert.Severity;
                alertCmd.Parameters["agent_id"].Value = (long)alert.AgentId;
                alertCmd.Parameters["triggering_sequence"].Value = (decimal)alert.SequenceNumber;
                alertCmd.Parameters["failure_count"].Value = (long)alert.FailureCounts;

                await alertCmd.ExecuteNonQueryAsync();
            }
        }

        await transaction.CommitAsync(cancellationToken);
    }
}
