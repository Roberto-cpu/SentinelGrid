/**
 * @file SecurityAlert.cs
 * @brief Defines the SecurityAlert record and related enumerations for security telemetry.
 *
 * This file contains the definition of the SecurityAlert record, which represents a security alert in the system,
 * and the AlertTypes and AlertSeverities enumerations, which define the types and severities of security alerts that can occur.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

namespace SentinelGrid.ControlPlane.Domain;

/**
 * @enum AlertTypes
 * @brief Represents different types of security alerts.
 *
 * The AlertTypes enumeration defines the various types of security alerts that can occur in the system,
 * such as repeated login failures and malicious requests.
 */
public enum AlertTypes : uint
{
    RepeatedLoginFailures = 1,
    MaliciousRequest = 2
};

/**
 * @enum AlertSeverities
 * @brief Represents different severities of security alerts.
 *
 * The AlertSeverities enumeration defines the various severities of security alerts that can occur in the system,
 * ranging from low to critical severity levels.
 */
public enum AlertSeverities : uint
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @record SecurityAlert
 * @brief Represents a security alert in the system.
 *
 * The SecurityAlert record encapsulates the details of a security alert, including the type, severity, agent ID,
 * sequence number, and failure counts. It is used to represent security alerts in the system for telemetry and analysis purposes.
 */
public sealed record SecurityAlert(
    AlertTypes Type,
    AlertSeverities Severity,
    uint AgentId,
    ulong SequenceNumber,
    uint FailureCounts
) : EngineMessage;


