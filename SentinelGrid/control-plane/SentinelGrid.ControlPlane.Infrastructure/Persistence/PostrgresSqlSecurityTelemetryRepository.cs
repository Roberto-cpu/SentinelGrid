/**
 * @file PostrgresSqlSecurityTelemetryRepository.cs
 * @brief Implements the ISecurityTelemetryRepository interface for PostgreSQL.
 *
 * This file contains the implementation of the ISecurityTelemetryRepository interface for storing security events and alerts in a PostgreSQL database.
 * It provides methods to store individual security events and alerts, as well as a method to store analysis results that include both events and alerts.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using Npgsql;
using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;


namespace SentinelGrid.ControlPlane.Infrastructure.Persistence;

/**
 * @class PostrgresSqlSecurityTelemetryRepository
 * @brief Implements the ISecurityTelemetryRepository interface for PostgreSQL.
 *
 * The PostrgresSqlSecurityTelemetryRepository class provides an implementation of the ISecurityTelemetryRepository interface for storing security events and alerts in a PostgreSQL database.
 * It includes methods to store individual security events and alerts, as well as a method to store analysis results that include both events and alerts.
 */
public sealed class PostrgresSqlSecurityTelemetryRepository : ISecurityTelemetryRepository
{
    private readonly NpgsqlDataSource _dataSource;

    /**
     * @brief Constructs a new PostrgresSqlSecurityTelemetryRepository.
     * @param dataSource The NpgsqlDataSource used for database connections.
     *
     * This constructor initializes a new instance of the PostrgresSqlSecurityTelemetryRepository class with the provided NpgsqlDataSource for database connections.
     */
    public PostrgresSqlSecurityTelemetryRepository(NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        _dataSource = dataSource;
    }

    /**
     * @brief Stores a security event in the PostgreSQL database.
     * @param securityEvent The security event to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method inserts the provided security event into the security_events table in the PostgreSQL database.
     * If a conflict occurs (i.e., an event with the same agent_id and sequence_number already exists), the insertion is ignored.
     */
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

    /**
     * @brief Stores a security alert in the PostgreSQL database.
     * @param securityAlert The security alert to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method inserts the provided security alert into the security_alerts table in the PostgreSQL database.
     * If a conflict occurs (i.e., an alert with the same alert_type, agent_id, and triggering_sequence already exists), the insertion is ignored.
     */
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

    /**
     * @brief Stores a security event and its associated alerts in the PostgreSQL database.
     * @param securityEvent The security event to be stored.
     * @param alerts The collection of security alerts associated with the event.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method inserts the provided security event and its associated alerts into the PostgreSQL database within a single transaction.
     * If a conflict occurs for either the event or any of the alerts, the insertion is ignored for that specific record.
     */
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
