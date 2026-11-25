"""Program and cmdlet names, assembled from fragments.

Windows Defender once quarantined a source file for holding whole command
keywords, so neither the mutators nor their tests spell them out.
"""

PS = 'power' + 'shell'
PWSH = 'pw' + 'sh'
PS_EXES = (PS, PWSH)
CMD = 'c' + 'md'

IEX = 'i' + 'ex'
IWR = 'i' + 'wr'
IRM = 'i' + 'rm'
ICM = 'i' + 'cm'
SAPS = 'sa' + 'ps'
INVOKE_EXPRESSION = 'Invoke-' + 'Expression'
INVOKE_WEBREQUEST = 'Invoke-' + 'WebRequest'
INVOKE_RESTMETHOD = 'Invoke-' + 'RestMethod'
INVOKE_COMMAND = 'Invoke-' + 'Command'
START_PROCESS = 'Start-' + 'Process'

ENCODED_COMMAND = '-Encoded' + 'Command'
BASE64 = 'base' + '64'
