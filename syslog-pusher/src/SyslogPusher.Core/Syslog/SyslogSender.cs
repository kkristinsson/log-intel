using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.Core.Syslog;

public sealed class SyslogSender : IAsyncDisposable
{
    private const int MaxQueueSize = 10_000;
    private static readonly TimeSpan InitialBackoff = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);

    private readonly AppConfiguration _configuration;
    private readonly ILogger<SyslogSender> _logger;
    private readonly object _queueLock = new();
    private readonly Queue<byte[]> _queue = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private Task? _worker;
    private TcpClient? _tcpClient;
    private NetworkStream? _tcpStream;
    private UdpClient? _udpClient;
    private long _dropped;

    public SyslogSender(AppConfiguration configuration, ILogger<SyslogSender> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public long DroppedCount => Interlocked.Read(ref _dropped);

    public void Start()
    {
        _worker = Task.Run(() => ProcessQueueAsync(_cts.Token));
    }

    public void Enqueue(SyslogMessage message)
    {
        var payload = SyslogFormatter.FormatRfc5424Bytes(message);
        lock (_queueLock)
        {
            while (_queue.Count >= MaxQueueSize)
            {
                _queue.Dequeue();
                Interlocked.Increment(ref _dropped);
            }

            _queue.Enqueue(payload);
        }

        _signal.Release();
    }

    private byte[]? TryDequeue()
    {
        lock (_queueLock)
        {
            return _queue.Count > 0 ? _queue.Dequeue() : null;
        }
    }

    private void RequeueFront(byte[] payload)
    {
        lock (_queueLock)
        {
            var items = _queue.ToArray();
            _queue.Clear();
            _queue.Enqueue(payload);
            foreach (var item in items)
            {
                if (_queue.Count >= MaxQueueSize)
                {
                    Interlocked.Increment(ref _dropped);
                    break;
                }

                _queue.Enqueue(item);
            }
        }

        _signal.Release();
    }

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
        var backoff = InitialBackoff;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _signal.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            while (true)
            {
                var payload = TryDequeue();
                if (payload is null)
                    break;

                try
                {
                    await SendPayloadAsync(payload, cancellationToken).ConfigureAwait(false);
                    backoff = InitialBackoff;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Failed to send syslog message; will retry");
                    await DisposeTcpAsync().ConfigureAwait(false);
                    RequeueFront(payload);
                    try
                    {
                        await Task.Delay(backoff, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }

                    backoff = TimeSpan.FromMilliseconds(
                        Math.Min(backoff.TotalMilliseconds * 2, MaxBackoff.TotalMilliseconds));
                    break;
                }
            }
        }
    }

    private async Task SendPayloadAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var destination = _configuration.Destination;
        if (destination.Protocol == SyslogProtocol.Udp)
        {
            _udpClient ??= new UdpClient();
            await _udpClient.SendAsync(payload, payload.Length, destination.Host, destination.Port)
                .ConfigureAwait(false);
            return;
        }

        await EnsureTcpConnectedAsync(destination, cancellationToken).ConfigureAwait(false);
        if (_tcpStream is null)
            throw new IOException("TCP syslog stream is not connected");

        await _tcpStream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken)
            .ConfigureAwait(false);
        await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureTcpConnectedAsync(SyslogDestination destination, CancellationToken cancellationToken)
    {
        if (_tcpClient is not null && _tcpStream is not null)
            return;

        await DisposeTcpAsync().ConfigureAwait(false);
        _tcpClient = new TcpClient();
        await _tcpClient.ConnectAsync(destination.Host, destination.Port, cancellationToken)
            .ConfigureAwait(false);
        _tcpStream = _tcpClient.GetStream();
    }

    private async Task DisposeTcpAsync()
    {
        if (_tcpStream is not null)
        {
            await _tcpStream.DisposeAsync().ConfigureAwait(false);
            _tcpStream = null;
        }

        _tcpClient?.Dispose();
        _tcpClient = null;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_worker is not null)
        {
            try
            {
                await _worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _udpClient?.Dispose();
        await DisposeTcpAsync().ConfigureAwait(false);
        _cts.Dispose();
        _signal.Dispose();
    }
}
