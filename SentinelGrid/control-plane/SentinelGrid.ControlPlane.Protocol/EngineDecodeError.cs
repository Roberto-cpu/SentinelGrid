/**
 * @enum EngineDecodeError
 * @brief Represents the possible errors that can occur during engine message decoding.
 *
 * The EngineDecodeError enumeration defines the various errors that can occur when decoding an engine message.
 * It includes values for no error, packet too small, invalid packet size, invalid magic, unsupported version,
 * invalid message type, invalid payload length, invalid agent ID, invalid sequence number, invalid event type,
 * invalid alert type, invalid severity, and invalid failure count.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @enum EngineDecodeError
 * @brief Represents the possible errors that can occur during engine message decoding.
 *
 * The EngineDecodeError enumeration defines the various errors that can occur when decoding an engine message.
 * It includes values for no error, packet too small, invalid packet size, invalid magic, unsupported version,
 * invalid message type, invalid payload length, invalid agent ID, invalid sequence number, invalid event type,
 * invalid alert type, invalid severity, and invalid failure count.
 */
public enum EngineDecodeError
{
    None,
    PacketTooSmall,
    InvalidPacketSize,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMessageType,
    InvalidPayloadLength,
    InvalidAgentId,
    InvalidSequenceNumber,
    InvalidEventType,
    InvalidAlertType,
    InvalidSeverity,
    InvalidFailureCount
}
