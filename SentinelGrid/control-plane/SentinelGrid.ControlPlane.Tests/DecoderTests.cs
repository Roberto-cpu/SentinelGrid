using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Protocol;
using System.Net.Sockets;

namespace SentinelGrid.ControlPane.Tests;

[TestClass]
public sealed class DecoderTests
{
    private static byte[] CreateValidEventPacket() =>
    [
        0x53, 0x47, 0x52, 0x44, // SGRD
        0x00, 0x01,             // Version
        0x00, 0x01,             // SecurityEvent
        0x00, 0x00, 0x00, 0x10, // Payload size 16

        0x00, 0x00, 0x00, 0x65, // Agent 10

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, // Sequence 3

        0x00, 0x00, 0x00, 0x03  // LoginFailed
    ];

    private static byte[] CreateValidAlertPacket() =>
    [
        0x53, 0x47, 0x52, 0x44, // SGRD
        0x00, 0x01,             // Version
        0x00, 0x02,             // SecurityAlert
        0x00, 0x00, 0x00, 0x18, // Payload size 24

        0x00, 0x00, 0x00, 0x01, // RepeatedLoginFailures
        0x00, 0x00, 0x00, 0x03, // High
        0x00, 0x00, 0x00, 0x65, // Agent 101

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, // Triggering sequence 3

        0x00, 0x00, 0x00, 0x03  // Failure count 3
    ];

    [TestMethod]
    public void TestValidEvent()
    {
        byte[] packet = CreateValidEventPacket();

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<SecurityEvent>(result.Message);
    }

    [TestMethod]
    public void TestValidAlert()
    {
        byte[] packet = CreateValidAlertPacket();

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<SecurityAlert>(result.Message);
    }

    [TestMethod]
    public void TestPacketTooSmall()
    {
        byte[] packet = CreateValidAlertPacket();

        for (int i = 0; i < EngineProtocolConstants.HeaderSize; ++i)
        {
            EngineDecodeResult result = EngineMessageDecoder.Decode(packet.AsSpan(0, i));
            Assert.IsFalse(result.IsSuccess);
            Assert.AreEqual(EngineDecodeError.PacketTooSmall, result.Error, $"Unexpected result for packet size {i}");
        }
    }

    [TestMethod]
    public void TestInvalidMagic()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[3] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidMagic, result.Error);
    }

    [TestMethod]
    public void TestUnsupportedVersion()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[5] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.UnsupportedVersion, result.Error);
    }

    [TestMethod]
    public void TestInvalidMessageType()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[7] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidMessageType, result.Error);
    }

    [TestMethod]
    public void TestInvalidEventPayloadLength()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[11] = 0x0F;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidPayloadLength, result.Error);
    }
    
    [TestMethod]
    public void TestInvalidAlertPayloadLength()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[11] = 0x17;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidPayloadLength, result.Error);
    }

    [TestMethod]
    public void TestInvalidPacketSize()
    {
        byte[] packet = CreateValidAlertPacket();

        for (int i = EngineProtocolConstants.HeaderSize; i < packet.Length; ++i)
        {

            EngineDecodeResult result = EngineMessageDecoder.Decode(packet.AsSpan(0, i));

            Assert.AreEqual(EngineDecodeError.InvalidPacketSize, result.Error, $"Failed for size {i}");
        }
    }

    [TestMethod]
    public void TestInvalidAgentId()
    {
        byte[] packet = CreateValidEventPacket();
        packet[15] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidAgentId, result.Error);
    }

    [TestMethod]
    public void TestInvalidSequenceNumber()
    {
        byte[] packet = CreateValidEventPacket();
        packet[23] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidSequenceNumber, result.Error);
    }

    [TestMethod]
    public void TestInvalidEventType()
    {
        byte[] packet = CreateValidEventPacket();
        packet[27] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidEventType, result.Error);
    }

    [TestMethod]
    public void TestInvalidAlertType()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[15] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidAlertType, result.Error);
    }

    [TestMethod]
    public void TestInvalidSeverity()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[19] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidSeverity, result.Error);
    }

    [TestMethod]
    public void TestInvalidFailuresCount()
    {
        byte[] packet = CreateValidAlertPacket();
        packet[35] = 0x00;

        EngineDecodeResult result = EngineMessageDecoder.Decode(packet);
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineDecodeError.InvalidFailureCount, result.Error);
    }
}
