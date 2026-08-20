using SentinelGrid.ControlPlane.Application.Persistence;
using SentinelGrid.ControlPlane.Domain;
using SentinelGrid.ControlPlane.Worker;
using SentinelGrid.ControlPlane.Worker.Messaging;
using SentinelGrid.ControlPlane.Worker.Workers;
using SentinelGrid.ControlPlane.Infrastructure.Persistence;
using Npgsql;

var builder = Host.CreateApplicationBuilder(args);

string connectionString = builder.Configuration.GetConnectionString("SentinelGrid") 
    ?? throw new InvalidOperationException("SentinelGrid PosgreSQL connection string missed");

builder.Services.AddSingleton(NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton(new EngineMessageQueue(capacity: 128));
builder.Services.AddSingleton<ISecurityTelemetryRepository, InMemorySecurityTelemetryRepository>();
builder.Services.AddHostedService<MessageProcessingWorker>();
builder.Services.AddHostedService<EngineTcpIngestionWorker>();

var host = builder.Build();
await host.RunAsync();
