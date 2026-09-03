/**
 * @file InMemorySecurityTelemetryRepository.cs
 * @brief Implements an in-memory repository for storing security telemetry data.
 *
 * The InMemorySecurityTelemetryRepository class provides an in-memory implementation of the ISecurityTelemetryRepository interface.
 * It allows for storing and retrieving security events and alerts in a thread-safe manner using concurrent queues.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using System.Collections.Concurrent;

namespace SentinelGrid.ControlPlane.Infrastructure.Persistence;

/**
 * @class InMemorySecurityTelemetryRepository
 * @brief Implements an in-memory repository for storing security telemetry data.
 *
 * The InMemorySecurityTelemetryRepository class provides an in-memory implementation of the ISecurityTelemetryRepository interface.
 * It allows for storing and retrieving security events and alerts in a thread-safe manner using concurrent queues.
 */
public class InMemorySecurityTelemetryRepository : ISecurityTelemetryRepository
{
    private readonly ConcurrentQueue<SecurityEvent> _events = new ();
    private readonly ConcurrentQueue<SecurityAlert> _alerts = new ();

    /**
     * @brief Stores a security event in the in-memory repository.
     * @param securityEvent The security event to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method enqueues the provided security event into the in-memory queue for events.
     */
    public Task StoreEventAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        _events.Enqueue(securityEvent);
        return Task.CompletedTask;
    }

    /**
     * @brief Stores a security alert in the in-memory repository.
     * @param securityAlert The security alert to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method enqueues the provided security alert into the in-memory queue for alerts.
     */
    public Task StoreAlertAsync(SecurityAlert securityAlert, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityAlert);
        cancellationToken.ThrowIfCancellationRequested();

        _alerts.Enqueue(securityAlert);
        return Task.CompletedTask;
    }

    /**
     * @brief Retrieves a snapshot of all stored security events.
     * @returns A read-only list of all stored security events.
     *
     * This method returns a snapshot of all security events currently stored in the in-memory repository.
     */
    public IReadOnlyList<SecurityEvent> GetEventsSnapshot() { return _events.ToArray(); }

    /**
     * @brief Retrieves a snapshot of all stored security alerts.
     * @returns A read-only list of all stored security alerts.
     *
     * This method returns a snapshot of all security alerts currently stored in the in-memory repository.
     */
    public IReadOnlyList<SecurityAlert> GetAlertsSnapshot() { return _alerts.ToArray(); }
}
