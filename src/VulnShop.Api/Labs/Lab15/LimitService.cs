namespace VulnShop.Api.Labs.Lab15;

/// <summary>
/// Lab15 – servis koji provjerava pravila transakcije (dnevni limit 1000 EUR).
///
/// Baca iznimku za nepoznatu valutu ili neispravan iznos, a <see cref="LimitExceededException"/>
/// ako je iznos iznad limita. Poanta vježbe je da RANJIVI kontroler ove iznimke "proguta"
/// (fail-open) umjesto da odbije transakciju. Ova klasa NIJE predmet popravka.
/// </summary>
public sealed class LimitService
{
    public static readonly IReadOnlySet<string> AllowedCurrencies = new HashSet<string>(StringComparer.Ordinal) { "EUR", "USD" };

    public const decimal DailyLimit = 1000.00m;

    /// <exception cref="ArgumentException">Nepoznata valuta ili neispravan iznos.</exception>
    /// <exception cref="LimitExceededException">Iznos premašuje dnevni limit.</exception>
    public void Check(decimal amount, string? currency)
    {
        if (currency is null || !AllowedCurrencies.Contains(currency))
        {
            throw new ArgumentException("Nepoznata valuta: " + currency);
        }
        if (amount <= 0)
        {
            throw new ArgumentException("Neispravan iznos: " + amount);
        }
        if (amount > DailyLimit)
        {
            throw new LimitExceededException($"Prekoračen dnevni limit od {DailyLimit} EUR.");
        }
    }
}

/// <summary>Iznos transakcije premašuje dnevni limit.</summary>
public sealed class LimitExceededException(string message) : Exception(message);
