using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Domain;

public enum EventTypes : uint
{
    Heartbeat = 1,
    LoginFailed = 2,
    ServiceStop = 3
};

public sealed record SecurityEvent(
    uint AgentId,
    ulong SequenceNumber,
    EventTypes Type
) : EngineMessage;