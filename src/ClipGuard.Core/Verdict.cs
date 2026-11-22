namespace ClipGuard.Core;

public enum ThreatLevel
{
    None,
    /// <summary>像是指令，可能合法（例如官方安裝指令），只提醒。</summary>
    Suspicious,
    /// <summary>具備假驗證詐騙特徵，應清空剪貼簿。</summary>
    Malicious,
}

public sealed record Verdict(ThreatLevel Level, IReadOnlyList<string> Reasons)
{
    public static readonly Verdict Clean = new(ThreatLevel.None, []);
}
