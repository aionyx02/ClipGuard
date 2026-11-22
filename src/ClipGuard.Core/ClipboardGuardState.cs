namespace ClipGuard.Core;

/// <summary>收到剪貼簿內容後，App 該做什麼。</summary>
public enum ClipboardAction
{
    /// <summary>不用動作（乾淨、空的、或使用者已確認的還原內容）。</summary>
    None,
    /// <summary>提醒但不清空。</summary>
    WarnSuspicious,
    /// <summary>清空剪貼簿並通知，原內容已存進隔離區。</summary>
    Quarantine,
}

/// <summary>
/// 剪貼簿防護的狀態機：判定、隔離、還原。純邏輯，App 只負責讀寫剪貼簿與顯示通知。
/// 不寫檔、不記錄；隔離內容只放在這個物件裡。
/// </summary>
public sealed class ClipboardGuardState
{
    // 從隔離區還原的內容：使用者已確認，剪貼簿還是這段文字時不再攔截。
    // 用內容比對，不用「略過下一次通知」：一次寫入可能觸發多次或零次 WM_CLIPBOARDUPDATE，
    // 旗標會錯位，結果不是還原後又被攔，就是下一次真正的複製被漏掉。
    private string? _trusted;

    /// <summary>被清空的原內容；沒有可還原的內容時為 null。</summary>
    public string? Quarantined { get; private set; }

    /// <summary>目前剪貼簿內容的判定（已被清空時為 None）。</summary>
    public ThreatLevel Level { get; private set; }

    /// <summary>剛攔截並清空了惡意指令，而且使用者之後還沒複製別的文字。</summary>
    public bool QuarantineActive { get; private set; }

    /// <summary>剪貼簿內容換過幾次，給「同一份內容只警告一次」用。</summary>
    public long Generation { get; private set; }

    public Verdict LastVerdict { get; private set; } = Verdict.Clean;

    /// <param name="text">剪貼簿目前的文字；沒有文字（空的、圖片、檔案）時為 null。</param>
    public ClipboardAction OnClipboardText(string? text)
    {
        if (text is null)
        {
            // 我們自己清空剪貼簿也會走到這裡，這時要保留「剛攔截」的狀態。
            if (!QuarantineActive)
            {
                Level = ThreatLevel.None;
                LastVerdict = Verdict.Clean;
                Generation++;
            }
            return ClipboardAction.None;
        }

        Generation++;
        QuarantineActive = false;

        if (_trusted is not null && text == _trusted)
        {
            // 使用者已確認可信，但它仍是會執行程式的指令，執行入口照樣溫和提醒。
            Level = ThreatLevel.Suspicious;
            return ClipboardAction.None;
        }
        _trusted = null;

        LastVerdict = CommandDetector.Analyze(text);
        switch (LastVerdict.Level)
        {
            case ThreatLevel.Malicious:
                Quarantined = text;
                QuarantineActive = true;
                Level = ThreatLevel.None;
                return ClipboardAction.Quarantine;
            case ThreatLevel.Suspicious:
                Level = ThreatLevel.Suspicious;
                return ClipboardAction.WarnSuspicious;
            default:
                Level = ThreatLevel.None;
                return ClipboardAction.None;
        }
    }

    /// <summary>開始還原：回傳要寫回剪貼簿的內容，並先把它標成可信（寫入引發的通知可能比寫入完成更早到）。</summary>
    public string? BeginRestore()
    {
        if (Quarantined is null) return null;
        _trusted = Quarantined;
        return Quarantined;
    }

    /// <summary>寫回剪貼簿的結果。失敗時保留隔離內容，讓使用者可以再試。</summary>
    public void EndRestore(bool succeeded)
    {
        if (succeeded)
        {
            Quarantined = null;
            QuarantineActive = false;
        }
        else
        {
            _trusted = null;
        }
    }
}
