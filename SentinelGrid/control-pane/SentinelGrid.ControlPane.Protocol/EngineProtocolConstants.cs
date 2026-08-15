using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPane.Protocol;
public static class EngineProtocolConstants
{
    public const uint MagicNumber = 0x53475244;
    public const ushort SupportedVersion = 1;

    public const int HeaderSize = 12;
    public const uint EventPayloadSize = 16;
    public const uint AlertPayloadSize = 24;
}