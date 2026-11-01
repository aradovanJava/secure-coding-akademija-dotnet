namespace VulnShop.Api.Labs.Lab04;

/// <summary>
/// Lab04 – A02 Security Misconfiguration (CWE-16, CWE-209, CWE-942, CWE-693).
///
/// Konfiguracija cjevovoda (pipelinea) aplikacije koja se poziva iz <c>Program.cs</c>:
/// CORS politika, rukovanje greškama i sigurnosna HTTP zaglavlja.
///
/// RANJIVO:
///  - CORS dopušta BILO KOJI origin uz vjerodajnice (<c>SetIsOriginAllowed(_ => true).AllowCredentials()</c>),
///  - developerska stranica s greškama (stack trace, nazivi klasa, putanje) uključena je UVIJEK, i u produkciji,
///  - ne postavlja se nijedno sigurnosno zaglavlje (nosniff, X-Frame-Options, CSP, Referrer-Policy).
/// </summary>
public static class Lab04Setup
{
    public static IServiceCollection AddLab04(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddCors(options => options.AddDefaultPolicy(policy => policy
            // RANJIVO: svaki origin je dopušten, a uz to se šalju i kolačići/vjerodajnice.
            .SetIsOriginAllowed(_ => true)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials()));
        return services;
    }

    public static WebApplication UseLab04ErrorHandling(this WebApplication app)
    {
        // RANJIVO: developerska stranica s detaljima iznimke uključena je bez obzira na okruženje.
        app.UseDeveloperExceptionPage();
        return app;
    }

    public static WebApplication UseLab04SecurityHeaders(this WebApplication app)
    {
        // RANJIVO: sigurnosna zaglavlja se ne postavljaju.
        return app;
    }
}
