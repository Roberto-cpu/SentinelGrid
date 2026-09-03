/**
 * @file EngineDecodeResult.cs
 * @brief Defines the EngineDecodeResult record struct.
 *
 * This file contains the definition of the EngineDecodeResult record struct, which represents the result of decoding an engine message,
 * including the decoded message and any potential decode errors. 
 * It provides a convenient way to represent the outcome of decoding an engine message.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @record struct EngineDecodeResult
 * @brief Represents the result of decoding an engine message.
 *
 * The EngineDecodeResult record struct encapsulates the result of decoding an engine message, including the decoded message
 * and any potential decode errors. It provides a convenient way to represent the outcome of decoding an engine message.
 */
public readonly record struct EngineDecodeResult(EngineMessage? Message, EngineDecodeError Error)
{
    /**
     * @brief Indicates whether the decode operation was successful and a valid message was obtained.
     *
     * This property returns true if the decode operation was successful (Error is None) and a valid message was obtained (Message is not null).
     * Otherwise, it returns false.
     */
    public bool IsSuccess => Error == EngineDecodeError.None && Message is not null;
}
