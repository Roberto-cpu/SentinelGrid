using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Worker.Messaging;
using System;
using System.Collections.Generic;
using System.Security.Permissions;
using System.Text;

namespace SentinelGrid.ControlPlane.Worker.Workers
{


    public sealed class SimpleMessageProducer : BackgroundService
    {
        private readonly EngineMessageQueue _queue;

        public SimpleMessageProducer(EngineMessageQueue queue) 
        {
            this._queue = queue;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                await this._queue.WriteAsync(new SecurityEvent(101U, 1UL, EventTypes.Heartbeat), stoppingToken);
                await this._queue.WriteAsync(new SecurityEvent(101U, 2UL, EventTypes.LoginFailed), stoppingToken);
                await this._queue.WriteAsync(new SecurityAlert(AlertTypes.RepeatedLoginFailures, AlertSeverities.High, 101U, 3UL, 3), stoppingToken);
            }
            finally
            {
                this._queue.Complete();
            }
        }
    }
}
