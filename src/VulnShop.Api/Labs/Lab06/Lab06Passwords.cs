using System.Security.Cryptography;
using System.Text;

namespace VulnShop.Api.Labs.Lab06;

/// <summary>
/// Lab06 (dio A) – pohrana lozinki kupaca.
///
/// RANJIVO (CWE-916, CWE-327): lozinka se "hashira" algoritmom MD5, bez soli i bez
/// iteracija. MD5 je brz (milijarde pokušaja u sekundi na GPU-u), a bez soli dvije iste
/// lozinke daju isti hash, pa se cijela baza razbija tablicama (CrackStation) ili
/// alatom hashcat (<c>-m 0</c>) uz rječnik.
/// </summary>
public static class Lab06Passwords
{
    /// <summary>RANJIVO: MD5 heks zapis lozinke (32 heksadecimalna znaka), bez soli.</summary>
    public static string Hash(string password) =>
        Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(password)));

    /// <summary>RANJIVO: usporedba MD5 heksa (uz to, ni usporedba nije u konstantnom vremenu).</summary>
    public static bool Verify(string password, string storedHash) =>
        Hash(password) == storedHash;
}
