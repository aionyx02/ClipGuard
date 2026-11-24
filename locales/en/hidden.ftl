# Hidden characters (legacy HiddenCharDetector, CoreStrings Hidden_*).

hidden-zero-width = { $count } zero-width character(s) (invisible, but they change the content)
hidden-tag = { $count } Unicode TAG character(s) (invisible; may hide instructions for AI)
# $samples: number of listed code points (1–3); $cp1..$cp3: "U+XXXX".
hidden-other-invisible = { $count } other invisible character(s) ({ $samples ->
        [1] { $cp1 }
        [2] { $cp1 }, { $cp2 }
       *[other] { $cp1 }, { $cp2 }, { $cp3 }
    })
hidden-bidi = { $count } bidi control character(s) (the text may display in a different order than it really is)
# $script: cyrillic | greek; $glyph: the letter; $code: its hex code point.
hidden-homoglyph = A { $script ->
        [cyrillic] Cyrillic
       *[greek] Greek
    } letter { $glyph } (U+{ $code }) that looks like a Latin letter is mixed into English words
hidden-trailing-newline = The command ends with a line break, so pasting it into a terminal runs it immediately
