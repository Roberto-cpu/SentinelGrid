/**
 * @file EngineTcpIngestionWorker.cs
 * @brief A background service that ingests messages from a TCP connection.
 *
 * The EngineTcpIngestionWorker class listens for incoming TCP connections on a specified port,
 * reads messages from connected clients, and writes them to an EngineMessageQueue for further processing.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Protocol;
using SentinelGrid.ControlPlane.Worker.Messaging;
using System.Net;
using System.Net.Sockets;

namespace SentinelGrid.ControlPlane.Worker.Workers;

/**
 * @class EngineTcpIngestionWorker
 * @brief A background service that ingests messages from a TCP connection.
 *
 * The EngineTcpIngestionWorker class is a hosted service that listens for incoming TCP connections on a specified port,
 * reads messages from connected clients, and writes them to an EngineMessageQueue for further processing.
 */
public class EngineTcpIngestionWorker : BackgroundService
{
    private readonly EngineMessageQueue _queue;
    private readonly ILogger<EngineTcpIngestionWorker> _logger;

    /**
     * @brief Constructs a new EngineTcpIngestionWorker.
     * @param queue The EngineMessageQueue to which messages will be written.
     * @param logger The logger used for logging information and errors.
     */
    public EngineTcpIngestionWorker(EngineMessageQueue queue, ILogger<EngineTcpIngestionWorker> logger) 
    {
        this._queue = queue;
        this._logger = logger;
    }

    /**
     * @brief Executes the background service to ingest messages from a TCP connection.
     * @param stoppingToken A token that can be used to cancel the operation.
     *
     * This method listens for incoming TCP connections on a specified port, reads messages from connected clients,
     * and writes them to the EngineMessageQueue for further processing. It runs until the service is stopped or the cancellation token is triggered.
     */
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

    /**
     * @brief Processes a connected client by reading messages from its network stream.
     * @param stream The network stream of the connected client.
     * @param cancellationToken A token that can be used to cancel the operation.
     *
     * This method continuously reads messages from the client's network stream, decodes them, and writes them to the EngineMessageQueue.
     * It handles different read statuses, including successful reads, peer closures, and invalid frames.
     */
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