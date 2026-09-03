/**
 * @file ISecurityTelemetryRepository.cs
 * @brief Defines the ISecurityTelemetryRepository interface for security telemetry persistence.
 *
 * This file contains the definition of the ISecurityTelemetryRepository interface, which provides methods for storing security events and alerts in a persistent storage.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Application.Persistence;

public interface ISecurityTelemetryRepository
{
    /**
     * @brief Stores a security event in the repository.
     * @param securityEvent The security event to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method is responsible for storing a security event in the repository. It takes a SecurityEvent object and a CancellationToken as parameters.
     */
    Task StoreEventAsync(SecurityEvent securityEvent, CancellationToken cancellationToken);

    /**
     * @brief Stores a security alert in the repository.
     * @param securityAlert The security alert to be stored.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method is responsible for storing a security alert in the repository. It takes a SecurityAlert object and a CancellationToken as parameters.
     */
    Task StoreAlertAsync(SecurityAlert securityAlert, CancellationToken cancellationToken);
}
