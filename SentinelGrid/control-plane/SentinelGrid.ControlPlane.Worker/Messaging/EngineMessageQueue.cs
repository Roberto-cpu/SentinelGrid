using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Channels;

using SentinelGrid.ControlPlane.Protocol;
using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Worker.Messaging;

public sealed class EngineMessageQueue
{
    private readonly Channel<EngineMessage> _channel;
   
    public EngineMessageQueue(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfZero(capacity, "Queue's capacity cannot be zero.");

        this._channel = Channel.CreateBounded<EngineMessage>(capacity);

        BoundedChannelOptions options = new(capacity) {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false
        };

        this._channel = Channel.CreateBounded<EngineMessage>(options);
    }

    public ValueTask WriteAsync(EngineMessage message, CancellationToken cancellationToken = default)
    {
        if (message == null) ArgumentNullException.ThrowIfNull(message);
        return this._channel.Writer.WriteAsync(message, cancellationToken);
    }

    public IAsyncEnumerable<EngineMessage> ReadAllAsync(CancellationToken cancellationToken) 
    {
        return this._channel.Reader.ReadAllAsync(cancellationToken);
    }

    public void Complete(Exception? error = null)
    {
        this._channel.Writer.TryComplete(error);
    }
}
