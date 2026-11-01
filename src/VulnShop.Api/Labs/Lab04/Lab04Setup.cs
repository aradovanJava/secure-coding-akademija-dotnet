using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration (CWE-16, CWE-209, CWE-942, CWE-693).
///
/// ISPRAVLJENO:
///  - CORS: samo originovi s popisa u konfiguraciji (<c>Lab04:AllowedOrigins</c>),
///  - detaljna stranica s greškom samo u okruženju Development; inače generički odgovor
///    (ProblemDetails) s korelacijskim ID-om, a detalji idu samo u log,
///  - sigurnosna zaglavlja na svakom odgovoru (nosniff, X-Frame-Options, CSP, Referrer-Policy).
/// </summary>
public static class Lab04Setup
{
    public static IServiceCollection AddLab04(this IServiceCollection services, IConfiguration configuration)
    {
        // ISPRAVLJENO: allowlista originova iz konfiguracije (appsettings.json → Lab04:AllowedOrigins).
        var allowedOrigins = configuration.GetSection("Lab04:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
        services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .WithOrigins(allowedOrigins)
            .WithMethods("GET", "POST", "PUT")
            .WithHeaders("Content-Type", "Authorization")));
        services.AddProblemDetails();
        return services;
    }

    public static WebApplication UseLab04ErrorHandling(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            // Detalji greške samo na razvojnom računalu.
            app.UseDeveloperExceptionPage();
        }
        else
        {
            // ISPRAVLJENO: generička poruka + korelacijski ID; detalji iznimke samo u logu.
            app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
            {
                var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
                var correlationId = context.TraceIdentifier;
                context.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("VulnShop.Api.Labs.Lab04.ErrorHandler")
                    .LogError(exception, "Neobrađena greška, correlationId={CorrelationId}", correlationId);

                var problem = new ProblemDetails
                {
                    Status = StatusCodes.Status500InternalServerError,
                    Title = "Došlo je do pogreške na poslužitelju.",
                    Detail = "Pokušajte ponovno ili se obratite podršci i navedite korelacijski ID.",
                };
                problem.Extensions["correlationId"] = correlationId;

                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
            }));
        }
        return app;
    }

    public static WebApplication UseLab04SecurityHeaders(this WebApplication app)
    {
        // ISPRAVLJENO: sigurnosna zaglavlja na SVAKOM odgovoru. Dodaju se neposredno prije slanja
        // odgovora (OnStarting), pa ih ima i odgovor koji je izradio rukovatelj greškama.
        // Ako je endpoint već postavio stroži CSP (npr. Lab08), on se ne prepisuje.
        app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "no-referrer";
                if (!headers.ContainsKey("Content-Security-Policy"))
                {
                    headers.ContentSecurityPolicy = "default-src 'self'";
                }
                return Task.CompletedTask;
            });
            await next();
        });
        return app;
    }
}
