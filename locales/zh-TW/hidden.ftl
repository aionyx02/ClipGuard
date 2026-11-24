# Hidden characters (legacy HiddenCharDetector, CoreStrings Hidden_*).

hidden-zero-width = 含零寬字元 { $count } 個（看不見，但會改變內容）
hidden-tag = 含 Unicode TAG 字元 { $count } 個（看不見，可能藏著給 AI 的指令）
# $samples: number of listed code points (1–3); $cp1..$cp3: "U+XXXX".
hidden-other-invisible = 含其他看不見的字元 { $count } 個（{ $samples ->
        [1] { $cp1 }
        [2] { $cp1 }、{ $cp2 }
       *[other] { $cp1 }、{ $cp2 }、{ $cp3 }
    }）
hidden-bidi = 含 Bidi 控制字元 { $count } 個（可讓文字顯示順序與實際內容不同）
# $script: cyrillic | greek; $glyph: the letter; $code: its hex code point.
hidden-homoglyph = 英文字裡混有長得像英文字母的 { $script ->
        [cyrillic] 西里爾
       *[greek] 希臘
    }字母 { $glyph }（U+{ $code }）
hidden-trailing-newline = 指令結尾有換行，貼進終端機會直接執行
