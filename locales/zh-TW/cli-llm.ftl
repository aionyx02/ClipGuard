# Tier 2（scan --llm、llm check）與 MCP 的 redteam profile。前綴 cli-。

## scan --llm / llm check

cli-llm-disabled = AI 功能未開啟（沒有 llm.toml，或 enabled = false），只顯示本機分析結果。
cli-llm-config-error = AI 設定檔無法使用（{ $code }）：{ $path }，只顯示本機分析結果。
cli-llm-refused-secrets = 內容含有機密，不會送到雲端模型，只顯示本機分析結果。
cli-llm-skipped = 本機分析沒有發現可疑指令，依設定（only_high_risk）不詢問模型。
cli-llm-failed = AI 解說已捨棄（{ $code }），只顯示本機分析結果。
cli-llm-heading = AI 解說（{ $provider } / { $model }；AI 只能提高風險，不能降低）：
cli-llm-level = AI 判定：{ $level }
cli-llm-techniques = 手法：{ $list }
cli-llm-check-ok = AI 端點正常：{ $provider } / { $model } 回傳的 JSON 通過驗證（樣本判定：{ $level }）。
cli-llm-check-failed = AI 端點檢查失敗：{ $code }

## mcp --profile redteam

cli-mcp-bench-too-many = 項目太多：每次最多 { $max } 筆。
cli-mcp-bench-id-too-long = 項目 id 太長：最多 { $max } 個字元。
cli-mcp-validator-missing = 無法啟動語法檢查器，請確認 --validator-cmd。
