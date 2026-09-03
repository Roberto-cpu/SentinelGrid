/**
 * @file SecurityEvent.cs
 * @brief Defines the SecurityEvent record and EventTypes enumeration for security telemetry.
 *
 * This file contains the definition of the SecurityEvent record, which represents a security event in the system,
 * and the EventTypes enumeration, which defines the types of security events that can occur.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace SentinelGrid.ControlPlane.Domain;

/**
 * @enum EventTypes
 * @brief Represents different types of security events.
 *
 * The EventTypes enumeration defines the various types of security events that can occur in the system,
 * such as heartbeat, login failed, and service stop events.
 */
public enum EventTypes : uint
{
    Heartbeat = 1,
    LoginFailed = 2,
    ServiceStop = 3
};

/**
 * @record SecurityEvent
 * @brief Represents a security event in the system.
 *
 * The SecurityEvent record encapsulates the details of a security event, including the agent ID, sequence number,
 * and the type of event. It is used to represent security events in the system for telemetry and analysis purposes.
 */
public sealed record SecurityEvent(
    uint AgentId,
    ulong SequenceNumber,
    EventTypes Type
) : EngineMessage;