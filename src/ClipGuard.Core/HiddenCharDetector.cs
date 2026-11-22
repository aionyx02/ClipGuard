using System.Globalization;

namespace ClipGuard.Core;

/// <summary>
/// 找出複製內容裡「看不見或偽裝過」的字元：
///   零寬字元 —— 讓指令或關鍵字在畫面上看起來正常，實際上多了東西；
///   Bidi 控制字元 —— Trojan Source，讓程式碼顯示順序和實際順序不同；
///   同形字 —— 西里爾／希臘字母混進英文單字（powershеll 的 е 是 U+0435）；
///   結尾換行 —— 像指令的文字貼進終端機會直接執行，來不及檢查。
/// 這些都只是提醒（Suspicious），不清空剪貼簿。
/// </summary>
public static class HiddenCharDetector
{
    // 太長的內容多半是文件或程式檔，逐字掃描仍便宜，但通知意義不大。
    private const int MaxLength = 100_000;

    public static Verdict Analyze(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > MaxLength)
            return Verdict.Clean;

        var reasons = new List<string>();

        var zeroWidth = CountZeroWidth(text);
        if (zeroWidth > 0)
            reasons.Add($"含零寬字元 {zeroWidth} 個（看不見，但會改變內容）");

        var bidi = text.Count(IsBidiControl);
        if (bidi > 0)
            reasons.Add($"含 Bidi 控制字元 {bidi} 個（可讓文字顯示順序與實際內容不同）");

        if (FindHomoglyph(text) is { } glyph)
            reasons.Add($"英文字裡混有長得像英文字母的 {ScriptName(glyph)}字母 {glyph}（U+{(int)glyph:X4}）");

        if (HasTrailingNewlineAfterCommand(text))
            reasons.Add("指令結尾有換行，貼進終端機會直接執行");

        return reasons.Count == 0 ? Verdict.Clean : new Verdict(ThreatLevel.Suspicious, reasons);
    }

    // ---------- 零寬字元 ----------

    private static int CountZeroWidth(string text)
    {
        var count = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            switch (c)
            {
                case '\u200B' or '\u2060' or '\uFEFF':
                    count++;
                    break;
                // ZWNJ / ZWJ 在 emoji 組合（👨‍👩‍👧）和阿拉伯文、印度系文字裡是正常用法。
                case '\u200C' or '\u200D':
                    if (!IsLegitJoiner(text, i)) count++;
                    break;
            }
        }
        return count;
    }

    private static bool IsLegitJoiner(string text, int i)
    {
        var prev = CodePointBefore(text, i);
        var next = CodePointAfter(text, i);
        if (prev is null || next is null) return false;
        if (text[i] == '\u200D' && IsEmojiLike(prev.Value) && IsEmojiLike(next.Value)) return true;
        return IsComplexScriptLetter(prev.Value) && IsComplexScriptLetter(next.Value);
    }

    private static int? CodePointBefore(string text, int i)
    {
        if (i == 0) return null;
        if (i >= 2 && char.IsLowSurrogate(text[i - 1]) && char.IsHighSurrogate(text[i - 2]))
            return char.ConvertToUtf32(text[i - 2], text[i - 1]);
        return text[i - 1];
    }

    private static int? CodePointAfter(string text, int i)
    {
        if (i + 1 >= text.Length) return null;
        if (char.IsHighSurrogate(text[i + 1]) && i + 2 < text.Length && char.IsLowSurrogate(text[i + 2]))
            return char.ConvertToUtf32(text[i + 1], text[i + 2]);
        return text[i + 1];
    }

    private static bool IsEmojiLike(int cp) =>
        cp >= 0x1F000                       // 大部分 emoji、膚色修飾
        || cp is >= 0x2600 and <= 0x27BF    // ♀ ♂ ⚕ ❤ 等符號
        || cp is >= 0x2B00 and <= 0x2BFF
        || cp == 0xFE0F;                    // emoji 變體選擇符

    // 希伯來文到印度系、東南亞文字的區段（U+0590–U+1CFF），ZWNJ/ZWJ 在這些文字裡控制字形連接。
    private static bool IsComplexScriptLetter(int cp)
    {
        if (cp is < 0x0590 or > 0x1CFF) return false;
        var cat = CharUnicodeInfo.GetUnicodeCategory(cp);
        return cat is UnicodeCategory.OtherLetter or UnicodeCategory.NonSpacingMark
            or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark;
    }

    // ---------- Bidi ----------

    private static bool IsBidiControl(char c) =>
        c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069';

    // ---------- 同形字 ----------

    // 外觀和 ASCII 字母幾乎一樣的西里爾、希臘字母（取常見、混淆度高的子集）。
    private static readonly HashSet<char> Confusables =
    [
        // 西里爾小寫：а е о р с у х і ј ѕ ԁ һ ӏ ԛ ԝ ү
        'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і', 'ј', 'ѕ', 'ԁ', 'һ', 'ӏ', 'ԛ', 'ԝ', 'ү',
        // 西里爾大寫：А В Е К М Н О Р С Т Х І Ј Ѕ Ү
        'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'Х', 'І', 'Ј', 'Ѕ', 'Ү',
        // 希臘小寫：ο ν ρ ι
        'ο', 'ν', 'ρ', 'ι',
        // 希臘大寫：Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ
        'Α', 'Β', 'Ε', 'Ζ', 'Η', 'Ι', 'Κ', 'Μ', 'Ν', 'Ο', 'Ρ', 'Τ', 'Υ', 'Χ',
    ];

    private static bool IsLatinLetter(char c) =>
        c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '\u00C0' and <= '\u024F' && char.IsLetter(c);

    private static bool IsCyrillicOrGreek(char c) =>
        c is >= '\u0370' and <= '\u03FF' or >= '\u0400' and <= '\u052F' or >= '\u1F00' and <= '\u1FFF';

    private static string ScriptName(char c) => c >= '\u0400' ? "西里爾" : "希臘";

    /// <summary>
    /// 兩種情形算同形字攻擊：
    ///  1. 同一個單字裡同時有英文字母和同形字（powershеll）；
    ///  2. 整段沒有任何「非同形」的西里爾／希臘字母（不像真的俄文、希臘文），
    ///     卻有一個全由同形字組成的單字夾在英文之間（echo һоѕt）。
    /// 純俄文、純希臘文的段落一定會出現非同形字母（и、л、λ…），所以不會誤判。
    /// </summary>
    private static char? FindHomoglyph(string text)
    {
        var words = SplitWords(text);
        var hasLatinWord = false;
        var hasGenuineForeign = false;
        char? allConfusableCandidate = null;

        foreach (var word in words)
        {
            var latin = false;
            char? confusable = null;
            var allConfusable = true;
            foreach (var c in word)
            {
                if (IsLatinLetter(c)) latin = true;
                if (Confusables.Contains(c)) confusable ??= c;
                else
                {
                    allConfusable = false;
                    if (IsCyrillicOrGreek(c) && char.IsLetter(c)) hasGenuineForeign = true;
                }
            }

            if (latin && confusable is not null) return confusable;
            if (latin) hasLatinWord = true;
            if (allConfusable && confusable is not null && word.Length >= 2) allConfusableCandidate ??= confusable;
        }

        return hasLatinWord && !hasGenuineForeign ? allConfusableCandidate : null;
    }

    private static IEnumerable<string> SplitWords(string text)
    {
        var start = -1;
        for (var i = 0; i <= text.Length; i++)
        {
            var inWord = i < text.Length && char.IsLetter(text[i]);
            if (inWord && start < 0) start = i;
            else if (!inWord && start >= 0)
            {
                yield return text[start..i];
                start = -1;
            }
        }
    }

    // ---------- 結尾換行 ----------

    private static readonly HashSet<string> ShellCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "sudo", "su", "git", "gh", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "python", "python3", "py",
        "node", "deno", "bun", "dotnet", "cargo", "go", "docker", "kubectl", "helm", "terraform", "az", "aws", "gcloud",
        "curl", "wget", "ssh", "scp", "rm", "del", "rmdir", "rd", "mv", "cp", "copy", "move", "chmod", "chown",
        "cd", "ls", "dir", "cat", "echo", "mkdir", "touch", "make", "apt", "apt-get", "yum", "dnf", "pacman",
        "brew", "winget", "choco", "scoop", "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "start",
        "iex", "irm", "iwr", "invoke-webrequest", "invoke-restmethod", "invoke-expression", "start-process",
        "set-executionpolicy", "reg", "net", "netsh", "sc", "taskkill", "schtasks", "wmic", "shutdown",
        "mshta", "certutil", "bitsadmin", "rundll32", "regsvr32", "msiexec", "conhost",
    };

    private static bool HasTrailingNewlineAfterCommand(string text)
    {
        if (!text.EndsWith('\n') && !text.EndsWith('\r')) return false;

        var body = text.TrimEnd('\r', '\n', ' ', '\t');
        if (body.Length == 0) return false;

        var lastLine = body[(body.LastIndexOfAny(['\r', '\n']) + 1)..].Trim();
        return LooksLikeShellCommand(lastLine);
    }

    private static bool LooksLikeShellCommand(string line)
    {
        // 去掉文件裡常見的提示字元：「$ git pull」「> npm i」「PS C:\> dir」
        if (line.StartsWith("$ ") || line.StartsWith("> ") || line.StartsWith("# ")) line = line[2..].TrimStart();
        else if (line.StartsWith("PS ") && line.IndexOf('>') is var gt and > 0) line = line[(gt + 1)..].TrimStart();
        if (line.Length == 0) return false;

        if (CommandDetector.Analyze(line).Level != ThreatLevel.None) return true;

        var tokens = line.Split([' ', '\t'], 3, StringSplitOptions.RemoveEmptyEntries);
        var program = tokens[0];
        if (program.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) program = program[..^4];

        var known = ShellCommands.Contains(program) || program.StartsWith("./") || program.StartsWith(".\\");
        if (!known) return false;

        // 「git 是版本控制工具」這種中文句子：指令後面直接接 CJK 字，不是在下指令。
        return tokens.Length == 1 || !IsCjk(tokens[1][0]);
    }

    private static bool IsCjk(char c) =>
        c is >= '\u3040' and <= '\u30FF'    // 平假名、片假名
            or >= '\u3400' and <= '\u9FFF'  // 中日韓漢字
            or >= '\uAC00' and <= '\uD7AF'  // 韓文
            or >= '\uFF00' and <= '\uFFEF'; // 全形
}
