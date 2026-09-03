/**
 * @file MessageProcessingWorker.cs
 * @brief This file contains the implementation of the MessageProcessingWorker class, which is responsible for processing messages from the EngineMessageQueue.
 *
 * The MessageProcessingWorker class is a background service that continuously reads messages from the EngineMessageQueue and processes them based on their type. It handles security events and alerts, storing them in the appropriate repository and logging relevant information.
 *
 * @note This file is part of the SentinelGrid Control Plane Worker project.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Worker.Messaging;

namespace SentinelGrid.ControlPlane.Worker.Workers;

/**
 * @class MessageProcessingWorker
 * @brief A background service that processes messages from the EngineMessageQueue.
 *
 * The MessageProcessingWorker class is a hosted service that continuously reads messages from the EngineMessageQueue and processes them based on their type. It handles security events and alerts, storing them in the appropriate repository and logging relevant information.
 */
public class MessageProcessingWorker : BackgroundService
{
    private readonly EngineMessageQueue _queue;
    private readonly ILogger<MessageProcessingWorker> _logger;
    private readonly ISecurityTelemetryRepository _repository;

    /**
     * @brief Constructs a new MessageProcessingWorker.
     * @param queue The EngineMessageQueue from which messages will be read.
     * @param logger The logger used for logging information and errors.
     * @param repository The repository used for storing security events and alerts.
     */
    public MessageProcessingWorker(EngineMessageQueue queue, ILogger<MessageProcessingWorker> logger, ISecurityTelemetryRepository repository)
    {
        this._queue = queue;
        this._logger = logger;
        this._repository = repository;
    }

    /**
     * @brief Executes the background service to process messages.
     * @param stoppingToken A token that can be used to cancel the operation.
     *
     * This method continuously reads messages from the EngineMessageQueue and processes them based on their type.
     * It handles security events and alerts, storing them in the appropriate repository and logging relevant information.
     */
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (EngineMessage message in this._queue.ReadAllAsync(stoppingToken))
        {
            switch (message)
            {
                case SecurityEvent securityEvent:
                    await _repository.StoreEventAsync(securityEvent, stoppingToken);
                    this._logger.LogInformation(
                        "Security Event: Agent={AgentId}, Sequence={Sequence}, Type={EventType}.",
                        securityEvent.AgentId, securityEvent.SequenceNumber, securityEvent.Type
                    );
                    break;
                case SecurityAlert securityAlert:
                    await _repository.StoreAlertAsync(securityAlert, stoppingToken);
                    this._logger.LogInformation(
                        "Security Alert: Agent={AgentId}, Severity={Severity}, Type={AlertType}, Failures Count={Failures}.",
                        securityAlert.AgentId, securityAlert.Severity, securityAlert.Type, securityAlert.FailureCounts
                    );
                    break;
                default:
                    this._logger.LogError("Unsupported message type: {MessageType}.", message.GetType().FullName);
                    break;

            }
        }
    }
}
