#!/usr/bin/env bash
# Rebuild reports from the completed October 2026 campaign; runs no cryptography.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
summaries=(
  results/liboqs/complete-indicators/summary.json
  results/openssl/complete-indicators/summary.json
  results/noble/resource-followup/summary.json
  results/circl/resource-followup/summary.json
  results/rustcrypto/completion/result.json
  results/bouncycastle/completion/result.json
)
args=()
for summary in "${summaries[@]}"; do
  args+=(--summary "$summary")
done
python3 common/merge-measurement-completion.py "${args[@]}"
python3 common/report-resource-percentages.py
python3 common/report-completed-resources.py "${args[@]}"
python3 common/render-completed-resources.py
python3 common/report-performance-tradeoffs.py
python3 common/audit-completion-reports.py
