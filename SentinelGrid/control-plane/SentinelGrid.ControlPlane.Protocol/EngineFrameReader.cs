using System;
using System.Collections.Generic;
using System.Text;
using System.Buffers.Binary;

namespace SentinelGrid.ControlPlane.Protocol;

public static class EngineFrameReader
{
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
