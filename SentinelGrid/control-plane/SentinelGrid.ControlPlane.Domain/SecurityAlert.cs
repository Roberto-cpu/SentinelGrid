using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Domain;

public enum AlertTypes : uint
{
    RepeatedLoginFailures = 1
};

public enum AlertSeverities : uint
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

public sealed record SecurityAlert(
    AlertTypes Type,
    AlertSeverities Severity,
    uint AgentId,
    ulong SequenceNumber,
    uint FailureCounts
) : EngineMessage;


