/**
 * @file EngineFrameReadResult.cs
 * @brief Defines the EngineFrameReadResult record struct and the EngineFrameReadStatus enum.
 *
 * This file contains the definition of the EngineFrameReadResult record struct, which represents the result of reading an engine frame,
 * including the decoded message, read status, and any potential decode errors. It also defines the EngineFrameReadStatus enum, which
 * enumerates the possible statuses of reading an engine frame.
 */

using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @enum EngineFrameReadStatus
 * @brief Represents the status of reading an engine frame.
 *
 * The EngineFrameReadStatus enumeration defines the possible statuses that can occur when reading an engine frame.
 * It includes values for success, peer closure, truncated header, truncated payload, and invalid frame.
 */
public enum EngineFrameReadStatus
{
    Success,
    PeerClosed,
    TruncatedHeader,
    TruncatedPayload,
    InvalidFrame
}

/**
 * @record struct EngineFrameReadResult
 * @brief Represents the result of reading an engine frame.
 *
 * The EngineFrameReadResult record struct encapsulates the result of reading an engine frame, including the decoded message,
 * read status, and any potential decode errors. It provides a convenient way to represent the outcome of reading an engine frame.
 */
public readonly record struct EngineFrameReadResult(
    EngineMessage? Message, 
    EngineFrameReadStatus Status, 
    EngineDecodeError DecodeError
)
{
    /**
     * @brief Indicates whether the read operation was successful and a valid message was obtained.
     *
     * This property returns true if the read operation was successful (Status is Success) and a valid message was obtained (Message is not null).
     * Otherwise, it returns false.
     */
    public bool IsSuccess => Status == EngineFrameReadStatus.Success && Message is not null;
}
