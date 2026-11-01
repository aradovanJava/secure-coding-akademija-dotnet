using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace VulnShop.Tests.Infrastructure;

/// <summary>Jedan zapis loga uhvaćen u testu.</summary>
public sealed record CapturedLogEntry(LogLevel Level, string Category, string Message);

/// <summary>
/// Vlastiti <see cref="ILoggerProvider"/> koji sve zapise loga sprema u memoriju, kako bi
/// test mogao provjeriti ŠTO je aplikacija zapisala (Lab14). Registrira se kroz
/// <c>factory.WithWebHostBuilder(b =&gt; b.ConfigureLogging(l =&gt; l.AddProvider(provider)))</c>.
/// </summary>
public sealed class InMemoryLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<CapturedLogEntry> _entries = new();

    public IReadOnlyList<CapturedLogEntry> Entries => _entries.ToArray();

    public ILogger CreateLogger(string categoryName) => new InMemoryLogger(categoryName, _entries);

    public void Dispose()
    {
    }

    private sealed class InMemoryLogger(string category, ConcurrentQueue<CapturedLogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            entries.Enqueue(new CapturedLogEntry(logLevel, category, formatter(state, exception)));
        }
    }
}
