# T01 — Nạp file rule có comment và dòng trống

## Cách chạy

```bash
.venv/bin/python src/main.py --check-rules \
    --rules-config TEST/BT3/T01_Rule_Loader/config.json \
    --rules-report TEST/BT3/T01_Rule_Loader/rules_report.jsonl 2> TEST/BT3/T01_Rule_Loader/engine.log
```

## Input

- `test.rules` — 5 rule thật xen với comment đầu file, comment thụt lề, dòng trống,
  1 rule bị comment (`# alert ...`, sid 3010099) và 1 rule viết trên 3 dòng nối bằng `\`.
- `disabled.rules` — 1 rule, nhưng file bị tắt trong config (`"enabled": false`).
- `config.json` — bật `test.rules`, tắt `disabled.rules`, khai báo thêm `missing.rules`
  (không tồn tại), `disabled_sids: [3010004]`.

## Output

- `rules_report.jsonl` — mọi rule loader đưa sang parser (kèm `file`, `line`, `status`).
- `engine.log` — cảnh báo trong quá trình nạp.

## Kết quả

| Nội dung | Kết quả |
|---|---|
| comment, comment thụt lề, dòng trống | bị bỏ, không xuất hiện trong `rules_report.jsonl` |
| rule bị comment (sid 3010099) | coi là comment → không nạp |
| rule A (dòng 4), rule B (dòng 9) | `valid` |
| rule C viết 3 dòng (bắt đầu dòng 10) | nối thành 1 rule, `valid`, `line=10` |
| rule D sid 3010004 | `status=disabled`, `reason="sid disabled by config"` |
| `disabled.rules` | không đọc; log `file disabled by config` |
| `missing.rules` | log `cannot read rule file`, các file khác vẫn nạp bình thường |
| tổng | `{'valid': 3, 'disabled': 1}` — chỉ 4 rule thật được đưa sang parser |
