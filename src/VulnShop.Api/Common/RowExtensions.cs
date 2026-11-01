using System.Globalization;

namespace VulnShop.Api.Common;

/// <summary>
/// Pomoćne metode za čitanje vrijednosti iz retka (<see cref="Db.Query"/>).
/// Novčani iznosi se u SQLiteu čuvaju kao TEXT ("1000.00") da se izbjegnu
/// pogreške zaokruživanja s REAL (double) tipom; računamo s <see cref="decimal"/>.
/// </summary>
public static class RowExtensions
{
    public static string GetString(this IReadOnlyDictionary<string, object?> row, string column) =>
        Convert.ToString(row[column], CultureInfo.InvariantCulture) ?? string.Empty;

    public static long GetInt64(this IReadOnlyDictionary<string, object?> row, string column) =>
        Convert.ToInt64(row[column], CultureInfo.InvariantCulture);

    public static decimal GetDecimal(this IReadOnlyDictionary<string, object?> row, string column) =>
        Money.Parse(row[column]);
}

/// <summary>Pretvorbe novčanih iznosa (decimal ↔ TEXT u bazi).</summary>
public static class Money
{
    public static decimal Parse(object? value) => value switch
    {
        null => 0m,
        decimal d => d,
        string s => decimal.Parse(s, NumberStyles.Number, CultureInfo.InvariantCulture),
        _ => Convert.ToDecimal(value, CultureInfo.InvariantCulture),
    };

    /// <summary>Format za pohranu u bazu: dvije decimale, točka kao separator.</summary>
    public static string ToDb(decimal value) => value.ToString("0.00", CultureInfo.InvariantCulture);
}
