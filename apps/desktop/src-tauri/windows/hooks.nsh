; NSIS installer hooks (bundle.windows.nsis.installerHooks).

; Uninstall removes the native messaging registration the app wrote for the
; current user: four HKCU keys and the manifests (docs/plan/phase-4.md §4.3).
; An update also runs the old uninstaller; skip it then, since the new version
; registers again when it starts.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --unregister-nmh'
  ${EndIf}
!macroend
