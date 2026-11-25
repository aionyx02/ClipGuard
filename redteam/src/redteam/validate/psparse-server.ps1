# PasteWarden red-team PowerShell parse server (docs/spikes/s8-syntax-validation.md).
#
# Reads JSONL requests {"id": <int>, "src": <string>} on stdin and writes
# {"id": <int>, "ok": <bool>, "errors": [{"id", "line", "column"}]} on stdout.
# The source text is only handed to Parser::ParseInput: nothing is invoked,
# dot-sourced or compiled into a script block. The response never contains
# the source text or any part of it (error messages are dropped; only the
# parser's ErrorId and the extent's start position are returned).
#
# The Python side rejects `using module` / `using assembly` before a request
# is sent, and runs this script inside an OS sandbox (no network, writes only
# to a temp dir, no exec).

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Keeps every response far below the Python side's output cap.
$MaxErrors = 50

$utf8 = [System.Text.UTF8Encoding]::new($false)
$stdin = [System.IO.StreamReader]::new(
    [Console]::OpenStandardInput(), $utf8, $false, 65536)
$stdout = [System.IO.StreamWriter]::new(
    [Console]::OpenStandardOutput(), $utf8, 65536)
$stdout.AutoFlush = $false
$stdout.NewLine = "`n"

function Write-Response([hashtable] $obj) {
    $stdout.WriteLine(($obj | ConvertTo-Json -Compress -Depth 4))
    $stdout.Flush()
}

Write-Response @{ ready = $true; version = $PSVersionTable.PSVersion.ToString() }

while ($true) {
    $line = $stdin.ReadLine()
    if ($null -eq $line) { break }
    $id = $null
    try {
        $req = $line | ConvertFrom-Json -Depth 2
        $id = [long] $req.id
        $src = [string] $req.src
        $tokens = $null
        $errs = $null
        [void] [System.Management.Automation.Language.Parser]::ParseInput(
            $src, [ref] $tokens, [ref] $errs)
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $errs) {
            if ($list.Count -ge $MaxErrors) { break }
            $list.Add([ordered] @{
                    id     = [string] $e.ErrorId
                    line   = [int] $e.Extent.StartLineNumber
                    column = [int] $e.Extent.StartColumnNumber
                })
        }
        Write-Response @{ id = $id; ok = ($errs.Count -eq 0); errors = $list.ToArray() }
    }
    catch {
        # Never include the exception message: it may quote the request.
        Write-Response @{ id = $id; fatal = 'server-exception' }
    }
}
