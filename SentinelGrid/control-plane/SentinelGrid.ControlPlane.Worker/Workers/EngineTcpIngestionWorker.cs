using SentinelGrid.ControlPlane.Protocol;
using SentinelGrid.ControlPlane.Worker.Messaging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SentinelGrid.ControlPlane.Worker.Workers;

public class EngineTcpIngestionWorker : BackgroundService
{
    private readonly EngineMessageQueue _queue;
    private readonly ILogger<EngineTcpIngestionWorker> _logger;

    public EngineTcpIngestionWorker(EngineMessageQueue queue, ILogger<EngineTcpIngestionWorker> logger) 
    {
        this._queue = queue;
        this._logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TcpListener listener = new(IPAddress.Loopback, 6060);
        listener.Start(backlog: 100);

        this._logger.LogInformation(
            "Server listening on {Address}:6060",
            IPAddress.Loopback
        );

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(stoppingToken);
                this._logger.LogInformation("Engine connection accepted from {Endpoint}", client.Client.RemoteEndPoint);

                await ProcessClientAsync(client.GetStream(), stoppingToken);
            }
        } 
        catch(OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("TCP ingestion stopped");
        }
        finally
        {
            listener.Stop();
            _queue.Complete();
        }
    }

    private async Task ProcessClientAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            EngineFrameReadResult result = await EngineFrameReader.ReadAsync(stream, cancellationToken);

            switch(result.Status)
            {
                case EngineFrameReadStatus.Success when result.Message is { } message:
                    await _queue.WriteAsync(message, cancellationToken);
                    break;

                case EngineFrameReadStatus.PeerClosed:
                    _logger.LogInformation("Client has closed the connection");
                    return;

                default:
                    _logger.LogWarning(
                        "Invalid client frame: Status={Status}, Error={Error}",
                        result.Status, result.DecodeError
                    );
                    return;
            }
        }
    }
}