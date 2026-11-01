using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Mvc;
using VulnShop.Api.Common;

namespace VulnShop.Api.Labs.Lab03;

/// <summary>
/// Lab03 – A01 Broken Access Control: Server-Side Request Forgery (CWE-918).
///
/// ISPRAVLJENO:
///  - dopuštene su samo sheme http i https,
///  - host se razrješava (DNS) i odbija se svaka adresa koja nije javna: loopback, privatne mreže
///    (10/8, 172.16/12, 192.168/16), link-local (169.254/16 – cloud metadata), 0.0.0.0, ::1,
///    fc00::/7, fe80::/10 …,
///  - ista se provjera ponavlja u trenutku spajanja (<c>ConnectCallback</c>) – zaštita od DNS rebindinga,
///  - preusmjeravanja su isključena, uz kratki timeout i ograničenje veličine odgovora.
/// </summary>
[ApiController]
[Route("api/lab03")]
[RequireAuth]
public sealed class Lab03PreviewController : ControllerBase
{
    private const int MaxChars = 2000;

    // ISPRAVLJENO: bez preusmjeravanja; spajanje samo na provjerene (javne) adrese.
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(3),
        ConnectCallback = ConnectToPublicAddressAsync,
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
        MaxResponseContentBufferSize = 1024 * 1024,
    };

    [HttpGet("preview")]
    public async Task<IActionResult> Preview([FromQuery] string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var target) ||
            (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
        {
            return BadRequest(new { error = "Dopušteni su samo http i https URL-ovi." });
        }

        // ISPRAVLJENO: provjera odredišta PRIJE slanja zahtjeva.
        IPAddress[] addresses;
        try
        {
            addresses = IPAddress.TryParse(target.DnsSafeHost, out var literal)
                ? new[] { literal }
                : await Dns.GetHostAddressesAsync(target.DnsSafeHost);
        }
        catch (SocketException)
        {
            return BadRequest(new { error = "Host nije moguće razriješiti." });
        }

        if (addresses.Length == 0 || addresses.Any(IsForbidden))
        {
            return BadRequest(new { error = "Odredište nije dopušteno." });
        }

        try
        {
            using var response = await Client.GetAsync(target);
            var body = await response.Content.ReadAsStringAsync();
            var content = body.Length > MaxChars ? body[..MaxChars] : body;
            return Ok(new { url, status = (int)response.StatusCode, content });
        }
        catch (Exception)
        {
            // Generička poruka – ne otkrivamo detalje interne mreže.
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "Dohvat nije uspio." });
        }
    }

    /// <summary>Je li adresa zabranjena (nije javna adresa na internetu)?</summary>
    public static bool IsForbidden(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b[0] == 0                                   // 0.0.0.0/8
                || b[0] == 10                                  // 10.0.0.0/8
                || b[0] == 127                                 // 127.0.0.0/8
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)  // 100.64.0.0/10 (CGNAT)
                || (b[0] == 169 && b[1] == 254)                // 169.254.0.0/16 (link-local, cloud metadata)
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)   // 172.16.0.0/12
                || (b[0] == 192 && b[1] == 168)                // 192.168.0.0/16
                || b[0] >= 224;                                // multicast i rezervirano
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return address.IsIPv6LinkLocal      // fe80::/10
                || address.IsIPv6SiteLocal      // fec0::/10
                || address.IsIPv6Multicast      // ff00::/8
                || (b[0] & 0xFE) == 0xFC;       // fc00::/7 (unique local)
        }

        return true; // nepoznata obitelj adresa – odbij
    }

    /// <summary>Spajanje samo na javne adrese – provjera u trenutku spajanja (DNS rebinding).</summary>
    private static async ValueTask<Stream> ConnectToPublicAddressAsync(
        SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken);
        var allowed = addresses.FirstOrDefault(a => !IsForbidden(a))
                      ?? throw new HttpRequestException("Odredište nije dopušteno.");
        if (addresses.Any(IsForbidden))
        {
            throw new HttpRequestException("Odredište nije dopušteno.");
        }

        var socket = new Socket(allowed.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(allowed, context.DnsEndPoint.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
