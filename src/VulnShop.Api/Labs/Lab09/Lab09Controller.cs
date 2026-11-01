using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab09;

/// <summary>
/// Lab09 – A05 Injection: OS command injection (CWE-78).
///
/// ISPRAVLJENO:
///  - stroga validacija (allowlista): dopuštena je samo IP adresa ili ime hosta
///    (<c>^[A-Za-z0-9.-]{1,253}$</c>) – znakovi &amp;, ;, |, razmak, $ … se odbijaju s 400,
///  - nema ljuske: koristi se <see cref="Ping"/> iz .NET-a umjesto pokretanja vanjske naredbe.
///    (Ako vanjski program baš treba pokrenuti: <c>ProcessStartInfo.ArgumentList</c>, bez cmd.exe/sh.)
/// </summary>
[ApiController]
[Route("api/lab09")]
public sealed partial class Lab09Controller : ControllerBase
{
    [GeneratedRegex("^[A-Za-z0-9.-]{1,253}$")]
    private static partial Regex HostnamePattern();

    [HttpGet("ping")]
    public async Task<IActionResult> Ping([FromQuery] string? host)
    {
        // ISPRAVLJENO: allowlista dopuštenih znakova / valjana IP adresa.
        if (string.IsNullOrEmpty(host) || (!IPAddress.TryParse(host, out _) && !HostnamePattern().IsMatch(host)))
        {
            return BadRequest(new { error = "Neispravan host. Dopuštena je IP adresa ili ime hosta." });
        }

        try
        {
            // ISPRAVLJENO: bez ljuske – Ping API šalje ICMP zahtjev izravno.
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(host, 2000);
            return Ok(new
            {
                host,
                reachable = reply.Status == IPStatus.Success,
                status = reply.Status.ToString(),
                roundtripMs = reply.RoundtripTime,
            });
        }
        catch (PingException)
        {
            return Ok(new { host, reachable = false, status = "Neuspjeh" });
        }
    }
}
