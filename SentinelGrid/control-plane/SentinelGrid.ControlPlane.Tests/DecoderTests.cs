using Microsoft.Extensions.Configuration;
using Npgsql;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Infrastructure.Persistence;
using SentinelGrid.ControlPlane.Protocol;
using System.Net.Sockets;

namespace SentinelGrid.ControlPane.Tests;

[TestClass]
public sealed class DecoderTests
{
    private static SecurityEvent CreateSecurityEventInstance(uint agent) { return new SecurityEvent(agent, ulong.MaxValue, EventTypes.LoginFailed); }
    private static SecurityAlert CreateSecurityAlertInstance(uint agent) { 
        return new SecurityAlert(
            AlertTypes.RepeatedLoginFailures,
            AlertSeverities.High,
            agent, 1UL,
            3
        ); 
    }

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

    [TestMethod]
    public async Task TestReadValidEvent()
    {
        await using var stream = new MemoryStream(CreateValidEventPacket());
        EngineFrameReadResult result = await EngineFrameReader.ReadAsync(stream);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<SecurityEvent>(result.Message);
    }

    [TestMethod]
    public async Task TestReadValidAlert()
    {
        await using var stream = new MemoryStream(CreateValidAlertPacket());
        EngineFrameReadResult result = await EngineFrameReader.ReadAsync(stream);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<SecurityAlert>(result.Message);
    }

    [TestMethod]
    public async Task TestReadPeerClosed()
    {
        await using var stream = new MemoryStream(Array.Empty<byte>());
        EngineFrameReadResult result = await EngineFrameReader.ReadAsync(stream);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineFrameReadStatus.PeerClosed, result.Status);
    }

    [TestMethod]
    public async Task TestReadTruncatedHeader()
    {
        await using var stream = new MemoryStream(CreateValidEventPacket());

        int offset = 0;
        while (offset < 11)
        {
            byte[] buffer = new byte[offset + 1];
            stream.Read(buffer, 0, buffer.Length);
            var subStream = new MemoryStream(buffer);
            EngineFrameReadResult result = await EngineFrameReader.ReadAsync(subStream);

            Assert.IsFalse(result.IsSuccess);
            Assert.AreEqual(EngineFrameReadStatus.TruncatedHeader, result.Status);

            offset++;
        }
    }

    [TestMethod]
    public async Task TestTruncatedPayload()
    {
        await using var stream = new MemoryStream(CreateValidEventPacket());
        byte[] buffer = new byte[EngineProtocolConstants.HeaderSize + 5];
        stream.Read(buffer, 0, buffer.Length);
        var subSream = new MemoryStream(buffer);

        EngineFrameReadResult result = await EngineFrameReader.ReadAsync(subSream);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineFrameReadStatus.TruncatedPayload, result.Status);
    }

    [TestMethod]
    public async Task TestInvalidFrame()
    {
        await using var stream = new MemoryStream(CreateValidEventPacket());
        
        byte[] buffer = new byte[EngineProtocolConstants.HeaderSize + EngineProtocolConstants.EventPayloadSize];
        stream.Read(buffer, 0, buffer.Length);
        buffer[3] = 0x00;
        
        var subSream = new MemoryStream(buffer);
        EngineFrameReadResult result = await EngineFrameReader.ReadAsync(subSream);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(EngineFrameReadStatus.InvalidFrame, result.Status);
        Assert.AreEqual(EngineDecodeError.InvalidMagic, result.DecodeError);
    }

    [TestMethod]
    public async Task TestCanecelledToken()
    {
        await using var stream = new MemoryStream(CreateValidEventPacket());
        CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();

        OperationCanceledException? capturedException = null;

        try
        {
            await EngineFrameReader.ReadAsync(stream, cts.Token);
        }
        catch (OperationCanceledException e)
        {
            capturedException = e;
        }

        Assert.IsNotNull(capturedException);
    }

    [TestMethod]
    public async Task TestRepositoryAddEvent()
    {
        SecurityEvent securityEvent = CreateSecurityEventInstance(101U);
        InMemorySecurityTelemetryRepository  repository = new InMemorySecurityTelemetryRepository();
        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);
        Assert.IsNotEmpty(repository.GetEventsSnapshot());
    }
    
    [TestMethod]
    public async Task TestRepositoryAddAlert()
    {
        SecurityAlert securityAlert = CreateSecurityAlertInstance(101U);
        InMemorySecurityTelemetryRepository  repository = new InMemorySecurityTelemetryRepository();
        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        await repository.StoreAlertAsync(securityAlert, cancellationTokenSource.Token);
        Assert.IsNotEmpty(repository.GetAlertsSnapshot());
    }

    [TestMethod]
    public async Task TestRepositoryCheckEventsFIFO()
    {
        SecurityEvent securityEvent1 = CreateSecurityEventInstance(101U);
        SecurityEvent securityEvent2 = CreateSecurityEventInstance(102U);
        InMemorySecurityTelemetryRepository repository = new InMemorySecurityTelemetryRepository();
        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        await repository.StoreEventAsync(securityEvent1, cancellationTokenSource.Token);
        await repository.StoreEventAsync(securityEvent2, cancellationTokenSource.Token);

        Assert.AreEqual(101U, repository.GetEventsSnapshot()[0].AgentId);
        Assert.AreEqual(102U, repository.GetEventsSnapshot()[1].AgentId);
    }

    [TestMethod]
    public async Task TestRepositoryAddAlertWithCancelledToken()
    {
        SecurityAlert securityAlert = CreateSecurityAlertInstance(101U);
        InMemorySecurityTelemetryRepository repository = new InMemorySecurityTelemetryRepository();
        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        bool exceptionCaptured = false;

        try
        {
            await repository.StoreAlertAsync(securityAlert, cancellationTokenSource.Token);
        }
        catch (OperationCanceledException)
        {
            exceptionCaptured = true;
        }

        Assert.IsTrue(exceptionCaptured);
    }

    [TestMethod]
    public async Task TestRepositoryAddNullAlert()
    {
        SecurityAlert securityAlert = null;
        InMemorySecurityTelemetryRepository repository = new InMemorySecurityTelemetryRepository();
        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
       
        bool exceptionCaptured = false;

        try
        {
            await repository.StoreAlertAsync(securityAlert, cancellationTokenSource.Token);
        }
        catch (ArgumentNullException)
        {
            exceptionCaptured = true;
        }

        Assert.IsTrue(exceptionCaptured);
    }

    [TestClass]
    public sealed class PostgreSqlConnectionTests {

        [TestMethod]
        public async Task StoreEvent()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                    .AddUserSecrets<PostgreSqlConnectionTests>(optional: false)
                    .Build();

            string connectionString =
                configuration.GetConnectionString("SentinelGrid")
                ?? throw new InvalidOperationException("Test connection string is missing.");

            SecurityEvent securityEvent = CreateSecurityEventInstance(101U);
            NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);


            PostrgresSqlSecurityTelemetryRepository repository = new PostrgresSqlSecurityTelemetryRepository(dataSource);

            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

            await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);

            await using NpgsqlCommand cmd = dataSource.CreateCommand("SELECT COUNT(*) FROM security_events");
            object? result = await cmd.ExecuteScalarAsync();

            Assert.IsGreaterThan(0, (long)result);
        }

        [TestMethod]
        public async Task StoreEventTwoTimes()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                    .AddUserSecrets<PostgreSqlConnectionTests>(optional: false)
                    .Build();

            string connectionString =
                configuration.GetConnectionString("SentinelGrid")
                ?? throw new InvalidOperationException("Test connection string is missing.");

            SecurityEvent securityEvent = CreateSecurityEventInstance(102U);
            NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);


            PostrgresSqlSecurityTelemetryRepository repository = new PostrgresSqlSecurityTelemetryRepository(dataSource);

            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

            await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);
            await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);

            await using NpgsqlCommand cmd = dataSource.CreateCommand("SELECT COUNT(*) FROM security_events");
            object? result = await cmd.ExecuteScalarAsync();

            Assert.AreEqual(4, (long)result);
        }

        [TestMethod]
        public async Task StoreEventMaxInt()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                    .AddUserSecrets<PostgreSqlConnectionTests>(optional: false)
                    .Build();

            string connectionString =
                configuration.GetConnectionString("SentinelGrid")
                ?? throw new InvalidOperationException("Test connection string is missing.");

            SecurityEvent securityEvent = CreateSecurityEventInstance(uint.MaxValue);
            NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);


            PostrgresSqlSecurityTelemetryRepository repository = new PostrgresSqlSecurityTelemetryRepository(dataSource);

            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

            await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);
            
            await using NpgsqlCommand cmd = dataSource.CreateCommand("SELECT COUNT(*) FROM security_events");
            object? result = await cmd.ExecuteScalarAsync();

            Assert.AreEqual(4, (long)result);
        }
        
        [TestMethod]
        public async Task TokenException()
        {
            IConfiguration configuration = new ConfigurationBuilder()
                    .AddUserSecrets<PostgreSqlConnectionTests>(optional: false)
                    .Build();

            string connectionString =
                configuration.GetConnectionString("SentinelGrid")
                ?? throw new InvalidOperationException("Test connection string is missing.");

            SecurityEvent securityEvent = CreateSecurityEventInstance(uint.MaxValue);
            NpgsqlDataSource dataSource = NpgsqlDataSource.Create(connectionString);


            PostrgresSqlSecurityTelemetryRepository repository = new PostrgresSqlSecurityTelemetryRepository(dataSource);

            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            bool exception = false;

            try {
            await repository.StoreEventAsync(securityEvent, cancellationTokenSource.Token);
            
            await using NpgsqlCommand cmd = dataSource.CreateCommand("SELECT COUNT(*) FROM security_events");
                object? result = await cmd.ExecuteScalarAsync();
            }
            catch(OperationCanceledException) { exception = true; }

            Assert.IsTrue(exception);
        }
    }
}
