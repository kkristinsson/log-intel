using System.Collections.Concurrent;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.Core.Syslog;

public sealed class SyslogSender : IAsyncDisposable
{
    private readonly AppConfiguration _configuration;
    private readonly ILogger<SyslogSender> _logger;
    private readonly ConcurrentQueue<byte[]> _queue = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private Task? _worker;
    private TcpClient? _tcpClient;
    private NetworkStream? _tcpStream;
    private UdpClient? _udpClient;

    public SyslogSender(AppConfiguration configuration, ILogger<SyslogSender> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public void Start()
    {
        _worker = Task.Run(() => ProcessQueueAsync(_cts.Token));
    }

    public void Enqueue(SyslogMessage message)
    {
        var payload = SyslogFormatter.FormatRfc5424Bytes(message);
        _queue.Enqueue(payload);
        _signal.Release();
    }

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
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

            while (_queue.TryDequeue(out var payload))
            {
                try
                {
                    await SendPayloadAsync(payload, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Failed to send syslog message");
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
            return;

        await _tcpStream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken)
            .ConfigureAwait(false);
        await _tcpStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureTcpConnectedAsync(SyslogDestination destination, CancellationToken cancellationToken)
    {
        if (_tcpClient?.Connected == true && _tcpStream is not null)
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
