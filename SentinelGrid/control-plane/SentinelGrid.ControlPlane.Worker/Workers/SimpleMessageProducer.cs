/**
 * @file SimpleMessageProducer.cs
 * @brief A simple message producer that generates security events and alerts.
 *
 * This file contains the implementation of the SimpleMessageProducer class, which is a background service
 * that produces security events and alerts for testing purposes. It writes these messages to an EngineMessageQueue.
 *
 * @author SentinelGrid Team
 * @date 2024-06-15
 */

using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Worker.Messaging;

namespace SentinelGrid.ControlPlane.Worker.Workers
{
    /**
     * @class SimpleMessageProducer
     * @brief A background service that produces security events and alerts.
     *
     * The SimpleMessageProducer class is a hosted service that generates a series of security events and alerts
     * and writes them to an EngineMessageQueue. It is intended for testing and demonstration purposes.
     */
    public sealed class SimpleMessageProducer : BackgroundService
    {
        private readonly EngineMessageQueue _queue;

        /**
         * @brief Initializes a new instance of the SimpleMessageProducer class.
         * @param queue The EngineMessageQueue to which messages will be written.
         */
        public SimpleMessageProducer(EngineMessageQueue queue) 
        {
            this._queue = queue;
        }

        /**
         * @brief Executes the background service to produce messages.
         * @param stoppingToken A token that can be used to cancel the operation.
         *
         * This method generates a series of security events and alerts and writes them to the EngineMessageQueue.
         * It runs until the service is stopped or the cancellation token is triggered.
         */
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
