using SentinelGrid.ControlPane.Domain;
using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPane.Protocol;

public readonly record struct EngineDecodeResult(EngineMessage? Message, EngineDecodeError Error)
{
    public bool IsSuccess => Error == EngineDecodeError.None && Message is not null;
}
