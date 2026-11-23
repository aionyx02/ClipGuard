using System.Globalization;
using System.Text;

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
    // 不因長度整段跳過（#19 的教訓）：每一項都是逐字線性掃描。唯一較貴的是 soft hyphen 那一行要不要
    // 跑指令判斷，所以最多判斷這麼多行，超過的行只做便宜的網址檢查。
    private const int MaxSoftHyphenCommandChecks = 256;

    public static Verdict Analyze(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return Verdict.Clean;

        var reasons = new List<string>();

        var zeroWidth = CountZeroWidth(text);
        if (zeroWidth > 0)
            reasons.Add(CoreStrings.Hidden_ZeroWidth(zeroWidth));

        var tags = CountTagChars(text);
        if (tags > 0)
            reasons.Add(CoreStrings.Hidden_Tag(tags));

        var (invisible, samples) = FindOtherInvisible(text);
        if (invisible > 0)
            reasons.Add(CoreStrings.Hidden_OtherInvisible(invisible, string.Join(CoreStrings.ListSeparator, samples.Select(cp => $"U+{cp:X4}"))));

        var bidi = text.Count(IsBidiControl);
        if (bidi > 0)
            reasons.Add(CoreStrings.Hidden_Bidi(bidi));

        if (FindHomoglyph(text) is { } glyph)
            reasons.Add(CoreStrings.Hidden_Homoglyph(ScriptName(glyph), glyph, ((int)glyph).ToString("X4", CultureInfo.InvariantCulture)));

        if (HasTrailingNewlineAfterCommand(text))
            reasons.Add(CoreStrings.Hidden_TrailingNewline);

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

    // ---------- Unicode TAG（U+E0000–U+E007F） ----------

    // TAG 字元把 ASCII 對應到看不見的 code point（U+E0020 是空白、U+E0061 是 a），整段英文都能藏進去給 AI 讀。
    // 在 UTF-16 裡都是代理對：高位 U+DB40，低位 U+DC00–U+DC7F。
    // 唯一的正常用法是 emoji 的區旗：🏴 + TAG 字母 + 結束 TAG（U+E007F）。只放行有標準圖案的三面旗
    // （英格蘭、蘇格蘭、威爾斯）；其他組合在各平台都只顯示成黑旗，TAG 部分一樣看不見，所以照算。
    private static readonly HashSet<string> RgiFlagTags = ["gbeng", "gbsct", "gbwls"];

    private static bool IsTagAt(string text, int i) =>
        i + 1 < text.Length && text[i] == '\uDB40' && text[i + 1] is >= '\uDC00' and <= '\uDC7F';

    private static int CountTagChars(string text)
    {
        var count = 0;
        for (var i = 0; i < text.Length; i++)
        {
            // 🏴 = U+1F3F4 = D83C DFF4
            if (text[i] == '\uD83C' && i + 1 < text.Length && text[i + 1] == '\uDFF4'
                && RgiFlagTagLength(text, i + 2) is var flag and > 0)
            {
                i += 1 + flag;
                continue;
            }
            if (IsTagAt(text, i))
            {
                count++;
                i++;
            }
        }
        return count;
    }

    // 從 start 開始若是標準區旗的 TAG 部分（含結束 TAG），回傳它佔的 UTF-16 長度，否則 0。
    private static int RgiFlagTagLength(string text, int start)
    {
        var spec = new StringBuilder(8);
        for (var i = start; IsTagAt(text, i) && spec.Length <= 8; i += 2)
        {
            if (text[i + 1] == '\uDC7F')
                return RgiFlagTags.Contains(spec.ToString()) ? i + 2 - start : 0;
            spec.Append((char)(text[i + 1] - 0xDC00));
        }
        return 0;
    }

    // ---------- 其他看不見的字元 ----------

    /// <summary>
    /// 不像零寬字元那樣常見，但一樣看不見、可以把關鍵字拆開或藏東西的字元：
    ///   U+00AD soft hyphen —— 只在換行處才顯示。德文等語言用來標斷字點（字母之間），這種情況放行，
    ///     除非所在的那行是指令或網址；
    ///   U+180E 蒙古文母音分隔符 —— 只有夾在蒙古文字母之間才放行；
    ///   U+115F / U+1160 韓文字首、字中填充字元 —— 只有拿來組合韓文字母（後面接母音、前面接子音）才放行；
    ///   U+3164、U+FFA0 韓文填充字元 —— 顯示成空白，常被拿來做「看不見的名字」，沒有現代的正常用法；
    ///   變體選擇符 —— 正常用法是一個字後面接一個（emoji 的 U+FE0F、漢字異體字 U+E0100–E01EF）。
    ///     連續好幾個可以逐 byte 藏資料（variation selector smuggling），所以連續兩個以上（不全是
    ///     U+FE0E / U+FE0F）、或 U+E0100 以上的接在非漢字後面就算。
    /// 回傳數量與最多三個不同的 code point（通知只顯示 code point，不顯示原文）。
    /// </summary>
    private static (int Count, List<int> Samples) FindOtherInvisible(string text)
    {
        var count = 0;
        var samples = new List<int>(3);
        void Hit(int cp)
        {
            count++;
            if (samples.Count < 3 && !samples.Contains(cp)) samples.Add(cp);
        }

        // 先拆成 code point（代理對算一個），offsets 記每個 code point 在原字串的位置。
        var cps = new List<int>(text.Length);
        var offsets = new List<int>(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            offsets.Add(i);
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                cps.Add(char.ConvertToUtf32(text[i], text[++i]));
            else
                cps.Add(text[i]);
        }

        var softHyphenLines = new Dictionary<int, bool>();
        var lineStart = 0;   // 往前掃時順便記住目前這行的開頭，不必每個 soft hyphen 都往回找
        for (var k = 0; k < cps.Count; k++)
        {
            var cp = cps[k];
            var prev = k > 0 ? cps[k - 1] : -1;
            var next = k + 1 < cps.Count ? cps[k + 1] : -1;
            if (cp is '\r' or '\n') lineStart = offsets[k] + 1;

            if (IsVariationSelector(cp))
            {
                var end = k;
                var allEmojiStyle = true;
                while (end < cps.Count && IsVariationSelector(cps[end]))
                    allEmojiStyle &= cps[end++] is 0xFE0E or 0xFE0F;
                if (end - k >= 2 && !allEmojiStyle)
                    for (var j = k; j < end; j++) Hit(cps[j]);
                else if (cp >= 0xE0100 && !IsIdeograph(prev)) Hit(cp);
                // 整串一次處理完再往後跳，連續很長的變體選擇符也是線性時間。
                k = end - 1;
                continue;
            }

            var suspicious = cp switch
            {
                0x00AD => IsSuspiciousSoftHyphen(text, offsets[k], lineStart, prev, next, softHyphenLines),
                0x180E => !(IsMongolian(prev) && IsMongolian(next)),
                0x115F => next is not (>= 0x1161 and <= 0x11A7 or >= 0xD7B0 and <= 0xD7C6),
                0x1160 => prev is not (>= 0x1100 and <= 0x115E or >= 0xA960 and <= 0xA97C),
                0x3164 or 0xFFA0 => true,
                _ => false,
            };
            if (suspicious) Hit(cp);
        }
        return (count, samples);
    }

    private static bool IsVariationSelector(int cp) => cp is >= 0xFE00 and <= 0xFE0F or >= 0xE0100 and <= 0xE01EF;

    private static bool IsMongolian(int cp) => cp is >= 0x1800 and <= 0x18AF;

    private static bool IsIdeograph(int cp) =>
        cp is >= 0x3400 and <= 0x4DBF or >= 0x4E00 and <= 0x9FFF or >= 0xF900 and <= 0xFAFF or >= 0x20000 and <= 0x3FFFF;

    private static bool IsLetter(int cp) =>
        cp >= 0 && Rune.IsValid(cp) && Rune.IsLetter(new Rune(cp));

    private static bool IsSuspiciousSoftHyphen(string text, int i, int lineStart, int prev, int next, Dictionary<int, bool> lineCache)
    {
        // 斷字點一定在兩個字母之間；在開頭、結尾、空白或符號旁邊都不是斷字。
        if (!IsLetter(prev) || !IsLetter(next)) return true;

        // 指令和網址裡不會有斷字點（例如 powe<SHY>rshell、exam<SHY>ple.com）。同一行只判斷一次。
        if (lineCache.TryGetValue(lineStart, out var cached)) return cached;
        var lineEnd = text.IndexOfAny(['\r', '\n'], i);
        var line = text[lineStart..(lineEnd < 0 ? text.Length : lineEnd)].Replace("\u00AD", "").Trim();
        var result = line.Contains("://") || line.Contains("www.", StringComparison.OrdinalIgnoreCase)
            || lineCache.Count < MaxSoftHyphenCommandChecks && LooksLikeShellCommand(line);
        lineCache[lineStart] = result;
        return result;
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

    private static string ScriptName(char c) => c >= '\u0400' ? CoreStrings.Hidden_ScriptCyrillic : CoreStrings.Hidden_ScriptGreek;

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
