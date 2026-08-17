using System;
using System.Collections.Generic;
using System.Text;
using SentinelGrid.ControlPlane.Domain;

namespace SentinelGrid.ControlPlane.Protocol;

public enum EngineFrameReadStatus
{
    Success,
    PeerClosed,
    TruncatedHeader,
    TruncatedPayload,
    InvalidFrame
}

public readonly record struct EngineFrameReadResult(
    EngineMessage? Message, 
    EngineFrameReadStatus Status, 
    EngineDecodeError DecodeError
)
{
    public bool IsSuccess => Status == EngineFrameReadStatus.Success && Message is not null;
}
