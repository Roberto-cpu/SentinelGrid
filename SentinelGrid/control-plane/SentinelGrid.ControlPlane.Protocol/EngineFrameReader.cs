/**
 * @file EngineFrameReader.cs
 * @brief Provides the EngineFrameReader class for reading engine frames from a stream.
 *
 * This file contains the definition of the EngineFrameReader class, which provides methods for reading engine frames from a stream.
 * It handles reading the frame header and payload, validating the frame structure, and decoding the message.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using System.Buffers.Binary;

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @class EngineFrameReader
 * @brief A static class that provides methods for reading engine frames from a stream.
 *
 * The EngineFrameReader class contains methods for reading engine frames from a stream. It handles reading the frame header and payload,
 * validating the frame structure, and decoding the message. It returns the result of the read operation, including the decoded message,
 * read status, and any potential decode errors.
 */
public static class EngineFrameReader
{
    /**
     * @brief Reads an engine frame from a stream asynchronously.
     * @param stream The stream to read the engine frame from.
     * @param cancellationToken A cancellation token to cancel the read operation.
     * @returns An EngineFrameReadResult containing the decoded message, read status, and any potential decode errors.
     *
     * This method reads an engine frame from the provided stream asynchronously. It handles reading the frame header and payload,
     * validating the frame structure, and decoding the message. It returns the result of the read operation, including the decoded message,
     * read status, and any potential decode errors.
     */
    public static async ValueTask<EngineFrameReadResult> ReadAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] header = new byte[EngineProtocolConstants.HeaderSize];
        int headerBytes = await ReadUntilFullOrClosedAsync(stream, header, cancellationToken).ConfigureAwait(false);

        if (headerBytes == 0)
            return new EngineFrameReadResult(null, EngineFrameReadStatus.PeerClosed, EngineDecodeError.None);
        else if (headerBytes < EngineProtocolConstants.HeaderSize)
            return new EngineFrameReadResult(null, EngineFrameReadStatus.TruncatedHeader, EngineDecodeError.PacketTooSmall);

        int declaredPayloadSize = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(8, sizeof(uint)));
        if (declaredPayloadSize > EngineProtocolConstants.AlertPayloadSize)
            return new EngineFrameReadResult(null, EngineFrameReadStatus.InvalidFrame, EngineDecodeError.InvalidPayloadLength);

        int payloadSize = checked((int) declaredPayloadSize);

        byte[] frame = new byte[EngineProtocolConstants.HeaderSize + payloadSize];
        header.AsSpan().CopyTo(frame);
        Memory<byte> payloadMemory = frame.AsMemory(EngineProtocolConstants.HeaderSize, payloadSize);

        int frameBytes = await ReadUntilFullOrClosedAsync(stream, payloadMemory, cancellationToken).ConfigureAwait(false);
        if (frameBytes < payloadSize)
            return new EngineFrameReadResult(null, EngineFrameReadStatus.TruncatedPayload, EngineDecodeError.InvalidPacketSize);

        EngineDecodeResult decodeResult = EngineMessageDecoder.Decode(frame);
        if (!decodeResult.IsSuccess)
            return new EngineFrameReadResult(null, EngineFrameReadStatus.InvalidFrame, decodeResult.Error);

        return new EngineFrameReadResult(decodeResult.Message, EngineFrameReadStatus.Success, EngineDecodeError.None);
    }

    /**
     * @brief Reads from a stream until the buffer is full or the stream is closed.
     * @param stream The stream to read from.
     * @param buffer The buffer to fill with data read from the stream.
     * @param cancellationToken A cancellation token to cancel the read operation.
     * @returns The total number of bytes read into the buffer.
     *
     * This method reads from the provided stream until the buffer is full or the stream is closed. It returns the total number of bytes read into the buffer.
     */
    private static async ValueTask<int> ReadUntilFullOrClosedAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[totalRead..], cancellationToken).ConfigureAwait(false);

            if (read == 0)
                break;
            
            totalRead += read;
        }

        return totalRead;
    }
}
