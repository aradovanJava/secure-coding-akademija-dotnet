using System.Runtime.Serialization;

namespace VulnShop.Api.Labs.Lab13;

/// <summary>
/// Lab13 – "gadget" klasa. Simulira stvarne gadget lance (npr. one iz alata ysoserial.net):
/// njezina metoda označena s <see cref="OnDeserializedAttribute"/> izvršava se AUTOMATSKI
/// TIJEKOM DESERIJALIZACIJE, prije nego što aplikacija uopće provjeri što je dobila.
///
/// Ovdje gadget samo zapisuje bezopasan tekst (<see cref="Content"/>) u marker datoteku
/// <see cref="ReportPath"/> – dovoljan dokaz da napadač upravlja tokom izvršavanja
/// (proizvoljan zapis datoteke). Ova klasa NIJE predmet popravka – popravlja se mjesto
/// deserijalizacije (<see cref="Lab13Controller"/>).
/// </summary>
public sealed class DiagnosticsTask
{
    public string? ReportPath { get; set; }

    public string? Content { get; set; }

    [OnDeserialized]
    internal void OnDeserialized(StreamingContext context)
    {
        if (!string.IsNullOrEmpty(ReportPath) && Content is not null)
        {
            File.WriteAllText(ReportPath, Content);
        }
    }
}
