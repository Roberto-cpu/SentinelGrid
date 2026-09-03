/**
 * @file EngineMessageTypes.cs
 * @brief Defines the EngineMessageTypes enumeration used in the SentinelGrid Control Plane protocol.
 *
 * This file contains the definition of the EngineMessageTypes enumeration, which represents different types of messages
 * that can be sent and received in the SentinelGrid Control Plane protocol. The enumeration values are used to identify
 * specific message types, such as security events and security alerts.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @enum EngineMessageTypes
 * @brief Represents different types of messages in the SentinelGrid Control Plane protocol.
 *
 * The EngineMessageTypes enumeration defines the various message types that can be sent and received in the
 * SentinelGrid Control Plane protocol. Each enumeration value corresponds to a specific message type, allowing
 * for easy identification and handling of messages during communication between components.
 */
public enum EngineMessageTypes : ushort
{
    SecurityEvent = 1,
    SecurityAlert = 2
};


