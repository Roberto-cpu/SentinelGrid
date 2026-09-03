/**
 * @file EngineProtocolConstants.cs
 * @brief Defines constants used in the engine protocol for SentinelGrid Control Plane.
 *
 * This file contains the definition of constants that are used in the engine protocol for communication
 * between different components of the SentinelGrid Control Plane. These constants include the magic number,
 * supported version, header size, and payload sizes for events and alerts.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @class EngineProtocolConstants
 * @brief A static class that defines constants used in the engine protocol.
 *
 * The EngineProtocolConstants class provides a set of constants that are used in the engine protocol for
 * communication between different components of the SentinelGrid Control Plane. These constants include
 * the magic number, supported version, header size, and payload sizes for events and alerts.
 */
public static class EngineProtocolConstants
{
    public const uint MagicNumber = 0x53475244;
    public const ushort SupportedVersion = 1;

    public const int HeaderSize = 12;
    public const uint EventPayloadSize = 16;
    public const uint AlertPayloadSize = 24;
}