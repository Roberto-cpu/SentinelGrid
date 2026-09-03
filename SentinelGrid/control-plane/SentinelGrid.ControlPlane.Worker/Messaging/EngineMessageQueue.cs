/**
 * @file EngineMessageQueue.cs
 * @brief Defines the EngineMessageQueue class for managing a bounded channel of EngineMessage objects.
 * 
 * This file contains the implementation of the EngineMessageQueue class, which provides a thread-safe queue for
 * handling EngineMessage objects. It uses a bounded channel to manage the flow of messages, allowing for asynchronous
 * writing and reading of messages. The queue can be completed with an optional error, signaling that no more messages
 * will be written.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using System.Threading.Channels;
using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Worker.Messaging;

/**
 * @class EngineMessageQueue
 * @brief A thread-safe queue for managing EngineMessage objects using a bounded channel.
 *
 * The EngineMessageQueue class provides a mechanism for asynchronously writing and reading EngineMessage objects
 * in a thread-safe manner. It uses a bounded channel to control the flow of messages, allowing for backpressure
 * when the queue is full. The queue can be completed with an optional error, signaling that no more messages
 * will be written.
 */
public sealed class EngineMessageQueue
{
    private readonly Channel<EngineMessage> _channel;

    /**
     * @brief Initializes a new instance of the EngineMessageQueue class with the specified capacity.
     * @param capacity The maximum number of messages that can be held in the queue.
     *
     * This constructor creates a bounded channel with the specified capacity, allowing for asynchronous writing
     * and reading of EngineMessage objects. If the capacity is zero, an ArgumentOutOfRangeException is thrown.
     */
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

    /**
     * @brief Asynchronously writes an EngineMessage to the queue.
     * @param message The EngineMessage to be written to the queue.
     * @param cancellationToken A token that can be used to cancel the operation.
     * @returns A ValueTask representing the asynchronous write operation.
     *
     * This method writes the specified EngineMessage to the queue. If the queue is full, it will wait until space
     * becomes available. If the message is null, an ArgumentNullException is thrown.
     */
    public ValueTask WriteAsync(EngineMessage message, CancellationToken cancellationToken = default)
    {
        if (message == null) ArgumentNullException.ThrowIfNull(message);
        return this._channel.Writer.WriteAsync(message, cancellationToken);
    }

    /**
     * @brief Asynchronously reads all EngineMessage objects from the queue.
     * @param cancellationToken A token that can be used to cancel the operation.
     * @returns An IAsyncEnumerable of EngineMessage objects read from the queue.
     *
     * This method returns an asynchronous enumerable that allows for reading all EngineMessage objects from the queue.
     * It will yield messages as they become available, and will complete when the queue is marked as complete.
     */
    public IAsyncEnumerable<EngineMessage> ReadAllAsync(CancellationToken cancellationToken) 
    {
        return this._channel.Reader.ReadAllAsync(cancellationToken);
    }

    /**
     * @brief Marks the queue as complete, optionally with an error.
     * @param error An optional exception that indicates an error occurred while writing to the queue.
     *
     * This method signals that no more messages will be written to the queue. If an error is provided, it will
     * be propagated to any readers of the queue. After calling this method, any further attempts to write to
     * the queue will result in an InvalidOperationException.
     */
    public void Complete(Exception? error = null)
    {
        this._channel.Writer.TryComplete(error);
    }
}
