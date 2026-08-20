using SentinelGrid.ControlPlane.Domain;
using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Application.Persistence;

public interface ISecurityTelemetryRepository
{
    Task StoreEventAsync(SecurityEvent securityEvent, CancellationToken cancellationToken);

    Task StoreAlertAsync(SecurityAlert securityAlert, CancellationToken cancellationToken);
}
