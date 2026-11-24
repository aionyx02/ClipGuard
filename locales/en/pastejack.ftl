# Pastejacking (legacy extension _locales pj_*).

pastejack-hidden = Contains invisible characters (zero-width or bidi control)
# $signal: powershell | mshta | cmd | pipe-shell | iex | lolbin | sudo (see pastejack-sig-*).
pastejack-added = Content added by the page { $signal ->
        [powershell] { pastejack-sig-powershell }
        [mshta] { pastejack-sig-mshta }
        [cmd] { pastejack-sig-cmd }
        [pipe-shell] { pastejack-sig-pipe-shell }
        [iex] { pastejack-sig-iex }
        [lolbin] { pastejack-sig-lolbin }
       *[sudo] { pastejack-sig-sudo }
    }
pastejack-newline = Adds a line break, so pasting it into a terminal runs it immediately
pastejack-replaced = What was written to the clipboard differs from the text you selected
pastejack-sig-powershell = calls PowerShell
pastejack-sig-mshta = calls mshta
pastejack-sig-cmd = calls cmd to run a command
pastejack-sig-pipe-shell = pipes a download straight into a shell
pastejack-sig-iex = runs content as code (iex)
pastejack-sig-lolbin = calls a commonly abused system program
pastejack-sig-sudo = runs a command with sudo
