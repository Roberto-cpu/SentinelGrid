/**
 * @file Program.cs
 * @brief The entry point for the SentinelGrid Control Plane Worker application.
 *
 * This file contains the main program that sets up and runs the SentinelGrid Control Plane Worker.
 * It configures services, including database connections, message queues, and hosted workers.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

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

builder.Services.AddSingleton<NpgsqlDataSource>(_ => NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton(new EngineMessageQueue(capacity: 128));
builder.Services.AddSingleton<ISecurityTelemetryRepository, PostrgresSqlSecurityTelemetryRepository>();
builder.Services.AddHostedService<MessageProcessingWorker>();
builder.Services.AddHostedService<EngineTcpIngestionWorker>();

var host = builder.Build();
await host.RunAsync();
