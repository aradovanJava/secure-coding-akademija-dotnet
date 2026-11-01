using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab09;

/// <summary>
/// Lab09 – A05 Injection: OS command injection (CWE-78).
///
/// RANJIVO: parametar <c>host</c> umeće se izravno u naredbeni redak ljuske
/// (Windows: <c>cmd.exe /c ping -n 1 &lt;host&gt;</c>, ostalo: <c>sh -c "ping -c 1 &lt;host&gt;"</c>).
/// Znakovi poput <c>&amp;</c>, <c>;</c> ili <c>|</c> omogućuju napadaču izvršavanje
/// proizvoljnih naredbi s ovlastima aplikacije.
/// </summary>
[ApiController]
[Route("api/lab09")]
public sealed class Lab09Controller : ControllerBase
{
    [HttpGet("ping")]
    public async Task<IActionResult> Ping([FromQuery] string? host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return BadRequest(new { error = "Parametar host je obavezan." });
        }

        // RANJIVO: korisnički unos postaje dio naredbe koju interpretira ljuska.
        var psi = new ProcessStartInfo();
        if (OperatingSystem.IsWindows())
        {
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c ping -n 1 " + host;
        }
        else
        {
            psi.FileName = "/bin/sh";
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("ping -c 1 " + host);
        }
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;

        try
        {
            using var process = Process.Start(psi)!;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            return Ok(new { host, exitCode = process.ExitCode, output = await stdout + await stderr });
        }
        catch (OperationCanceledException)
        {
            return StatusCode(StatusCodes.Status504GatewayTimeout, new { error = "Isteklo vrijeme izvršavanja." });
        }
        catch (Exception)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new { error = "Izvršavanje nije uspjelo." });
        }
    }
}
