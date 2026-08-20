using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Worker.Messaging;
using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Worker.Workers;

public class MessageProcessingWorker : BackgroundService
{
    private readonly EngineMessageQueue _queue;
    private readonly ILogger<MessageProcessingWorker> _logger;
    private readonly ISecurityTelemetryRepository _repository;

    public MessageProcessingWorker(EngineMessageQueue queue, ILogger<MessageProcessingWorker> logger, ISecurityTelemetryRepository repository)
    {
        this._queue = queue;
        this._logger = logger;
        this._repository = repository;
    }

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
