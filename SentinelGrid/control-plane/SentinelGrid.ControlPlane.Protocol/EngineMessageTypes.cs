using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Protocol;

public enum EngineMessageTypes : ushort
{
    SecurityEvent = 1,
    SecurityAlert = 2
};


