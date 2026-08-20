using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SentinelGrid.ControlPlane.Infrastructure.Persistence;

public class InMemorySecurityTelemetryRepository : ISecurityTelemetryRepository
{
    private readonly ConcurrentQueue<SecurityEvent> _events = new ();
    private readonly ConcurrentQueue<SecurityAlert> _alerts = new ();

    public Task StoreEventAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        _events.Enqueue(securityEvent);
        return Task.CompletedTask;
    }

    public Task StoreAlertAsync(SecurityAlert securityAlert, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityAlert);
        cancellationToken.ThrowIfCancellationRequested();

        _alerts.Enqueue(securityAlert);
        return Task.CompletedTask;
    }

    public IReadOnlyList<SecurityEvent> GetEventsSnapshot() { return _events.ToArray(); }
    public IReadOnlyList<SecurityAlert> GetAlertsSnapshot() { return _alerts.ToArray(); }
}
