# Command detection (crates/core/src/command). Legacy CommandDetector reasons
# (zh-TW only in the legacy app; translated here) and CoreStrings Explain_*.

## Verdict reasons: execution signals

cmd-reason-powershell = Calls PowerShell
cmd-reason-mshta = Calls mshta (often used to run a remote HTA)
cmd-reason-cmd = Calls cmd to run a command
cmd-reason-delayed-expansion = cmd delayed expansion (builds the command from !variables!)
cmd-reason-certutil = Uses certutil to download a file
cmd-reason-bitsadmin = Uses bitsadmin to download a file
cmd-reason-rundll32 = Uses rundll32 to run a script or remote file
cmd-reason-regsvr32 = Uses regsvr32 to load a remote script
cmd-reason-msiexec = Uses msiexec to install a remote package
cmd-reason-conhost = Uses conhost to run without a window
cmd-reason-curl-shell = Downloads something and hands it straight to a shell
cmd-reason-script-host = Uses wscript/cscript to run a script
cmd-reason-html-help = Uses hh to open a help file (can embed scripts)
cmd-reason-cmstp = Uses cmstp to install a profile (can run programs)
cmd-reason-pcalua = Uses pcalua to start a program indirectly
cmd-reason-odbcconf = Uses odbcconf to load a DLL
cmd-reason-installutil = Uses InstallUtil to run a .NET program
cmd-reason-ftp-script = Uses ftp to run a command script
cmd-reason-remote-file = Runs a file from a network share (UNC/WebDAV)
cmd-reason-webdav = Connects to a remote WebDAV folder
cmd-reason-search-ms = Uses search-ms: to open a search window (can point to a remote folder)
cmd-reason-ms-msdt = Uses ms-msdt: to call the troubleshooting tool (Follina technique)
cmd-reason-net-use = Maps a network drive and runs a file from it
cmd-reason-download-exec = Downloads and runs code directly

## Verdict reasons: scam signals

cmd-reason-hidden-window = Runs with a hidden window
cmd-reason-encoded = Runs a Base64-encoded command
cmd-reason-iex = Runs downloaded content as code (iex)
cmd-reason-download = Downloads content from the internet
cmd-reason-bait-comment = Bait comment (pretends to be a human verification)
cmd-reason-check-mark = Contains check marks (common in fake verifications)
cmd-reason-padding = Uses lots of spaces to push the real command out of view
cmd-reason-mshta-remote = mshta runs a remote URL directly
cmd-reason-unofficial-source = The download-and-run source is not a known official installer site

## Explanations
# $count = number of source hosts (0 = unknown source), $h1..$h3 = host names (at most 3).

cmd-explain-separator = {"; "}
cmd-explain-display = What it does: { $summary }
cmd-explain-decoded = Decoded: { $decoded }
cmd-explain-download-and-run =
    { $count ->
        [0] Downloads and runs code from the internet
        [1] Downloads and runs code from { $h1 }
        [2] Downloads and runs code from { $h1 }, { $h2 }
       *[other] Downloads and runs code from { $h1 }, { $h2 }, { $h3 }
    }
cmd-explain-regsvr32 =
    { $count ->
        [0] Loads and runs a remote script from the internet
        [1] Loads and runs a remote script from { $h1 }
        [2] Loads and runs a remote script from { $h1 }, { $h2 }
       *[other] Loads and runs a remote script from { $h1 }, { $h2 }, { $h3 }
    }
cmd-explain-msiexec =
    { $count ->
        [0] Downloads and installs a package from the internet
        [1] Downloads and installs a package from { $h1 }
        [2] Downloads and installs a package from { $h1 }, { $h2 }
       *[other] Downloads and installs a package from { $h1 }, { $h2 }, { $h3 }
    }
cmd-explain-download-file =
    { $count ->
        [0] Downloads a file from the internet
        [1] Downloads a file from { $h1 }
        [2] Downloads a file from { $h1 }, { $h2 }
       *[other] Downloads a file from { $h1 }, { $h2 }, { $h3 }
    }
cmd-explain-mshta-host = Uses mshta to run a program hosted on { $host }
cmd-explain-mshta-script = Uses mshta to run a script
cmd-explain-rundll32 = Uses rundll32 to run a script
cmd-explain-start-process-admin = Starts another program as administrator
cmd-explain-start-process = Starts another program
cmd-explain-hidden = Hides its window so you can't see what it does
cmd-explain-bypass = Turns off PowerShell's script safety restrictions
cmd-explain-defender = Changes Windows Defender settings
cmd-explain-encoded-undecodable = Hides an encoded command that couldn't be decoded
cmd-explain-encoded = Hides an encoded command
cmd-explain-generic = Runs system commands
cmd-explain-delayed-expansion = Uses cmd delayed expansion (!var!) to split up and hide the command
cmd-explain-script-host = Uses wscript/cscript to run a script file
cmd-explain-html-help = Uses hh to open a help file, which can hide a script
cmd-explain-cmstp = Uses cmstp to install a connection profile, which can run any program
cmd-explain-pcalua = Uses pcalua to start another program indirectly
cmd-explain-odbcconf = Uses odbcconf to load and run a DLL
cmd-explain-installutil = Uses InstallUtil to run a .NET program
cmd-explain-ftp-script = Uses ftp to run a command script
cmd-explain-remote-file-host = Runs a file from a network share on { $host }
cmd-explain-remote-file = Runs a file from a network share
cmd-explain-webdav-host = Connects to a remote WebDAV folder on { $host }
cmd-explain-webdav = Connects to a remote WebDAV folder
cmd-explain-net-use = Maps a network drive and runs a program from it
cmd-explain-search-ms = Uses search-ms: to open a search window whose files may come from a remote server
cmd-explain-ms-msdt = Uses ms-msdt: to call the troubleshooting tool (the Follina exploit technique)
