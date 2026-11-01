using Microsoft.Data.Sqlite;

namespace VulnShop.Api.Common;

/// <summary>
/// Jednostavan omotač oko JEDNE otvorene in-memory SQLite veze (<c>Data Source=:memory:</c>).
/// Registriran je kao singleton, pa svaka instanca aplikacije (i svaka WebApplicationFactory
/// u testovima) dobiva svoju, svježu bazu. Baza živi dok je veza otvorena.
///
/// Budući da <see cref="SqliteConnection"/> nije sigurna za istodobno korištenje iz više
/// dretvi, svaki pristup ide kroz <see cref="Use{T}"/> / <see cref="Run"/> koji zaključavaju vezu.
/// Ovdje NEMA ranjivosti – ranjivosti su u kodu pojedinih vježbi (Labs/LabXX).
/// </summary>
public sealed class Db : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly object _sync = new();

    public Db()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    /// <summary>Izvršava rad nad vezom pod ključem i vraća rezultat.</summary>
    public T Use<T>(Func<SqliteConnection, T> work)
    {
        lock (_sync)
        {
            return work(_connection);
        }
    }

    /// <summary>Izvršava rad nad vezom pod ključem (bez rezultata).</summary>
    public void Run(Action<SqliteConnection> work)
    {
        lock (_sync)
        {
            work(_connection);
        }
    }

    /// <summary>Parametrizirani SELECT – vraća retke kao rječnike (naziv stupca → vrijednost).</summary>
    public List<Dictionary<string, object?>> Query(string sql, params (string Name, object? Value)[] parameters) =>
        Use(conn =>
        {
            using var cmd = CreateCommand(conn, sql, parameters);
            return ReadAll(cmd);
        });

    /// <summary>Parametrizirani INSERT/UPDATE/DELETE – vraća broj promijenjenih redaka.</summary>
    public int Execute(string sql, params (string Name, object? Value)[] parameters) =>
        Use(conn =>
        {
            using var cmd = CreateCommand(conn, sql, parameters);
            return cmd.ExecuteNonQuery();
        });

    /// <summary>Parametrizirani upit koji vraća jednu vrijednost (prvi stupac prvog retka).</summary>
    public object? Scalar(string sql, params (string Name, object? Value)[] parameters) =>
        Use(conn =>
        {
            using var cmd = CreateCommand(conn, sql, parameters);
            var result = cmd.ExecuteScalar();
            return result is DBNull ? null : result;
        });

    public static SqliteCommand CreateCommand(
        SqliteConnection conn, string sql, params (string Name, object? Value)[] parameters)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
        return cmd;
    }

    /// <summary>Parametrizirani SELECT unutar zadane transakcije (za rad unutar <see cref="Use{T}"/>).</summary>
    public static List<Dictionary<string, object?>> QueryIn(
        SqliteConnection conn, SqliteTransaction? tx, string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = CreateCommand(conn, sql, parameters);
        cmd.Transaction = tx;
        return ReadAll(cmd);
    }

    /// <summary>Parametrizirani INSERT/UPDATE/DELETE unutar zadane transakcije.</summary>
    public static int ExecuteIn(
        SqliteConnection conn, SqliteTransaction? tx, string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = CreateCommand(conn, sql, parameters);
        cmd.Transaction = tx;
        return cmd.ExecuteNonQuery();
    }

    public static List<Dictionary<string, object?>> ReadAll(SqliteCommand cmd)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
            {
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            }
            rows.Add(row);
        }
        return rows;
    }

    public void Dispose() => _connection.Dispose();
}
