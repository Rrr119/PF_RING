#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${FB_ACCEPTANCE_BUILD_DIR:-/tmp/pfring-flow-balance-acceptance}"
THRESHOLD_BPS="${FB_DEVIATION_BPS:-1000}"

mkdir -p "${BUILD_DIR}"

cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  "${ROOT}/userland/lib/pfring_flow_balance.c" \
  "${ROOT}/tests/flow_balance_acceptance.c" \
  -I"${ROOT}/userland/lib" \
  -lpthread \
  -o "${BUILD_DIR}/flow_balance_acceptance"

DROP_JSON="${BUILD_DIR}/queue-drop-stats.json"
DIST_JSON="${BUILD_DIR}/distribution-stats.json"

"${BUILD_DIR}/flow_balance_acceptance" \
  --queues 4 \
  --flows "${FB_FLOWS:-4096}" \
  --packets "${FB_PACKETS_PER_FLOW:-32}" \
  --threshold-bps "${THRESHOLD_BPS}" \
  --json "${DROP_JSON}" \
  --distribution-json "${DIST_JSON}" \
  --verbose

python3 - "${DROP_JSON}" "${DIST_JSON}" "${THRESHOLD_BPS}" <<'PY'
import json
import sys

drop_path, dist_path, threshold_arg = sys.argv[1:4]
threshold_bps = int(threshold_arg)

with open(drop_path, encoding="utf-8") as f:
    drop = json.load(f)
with open(dist_path, encoding="utf-8") as f:
    dist = json.load(f)

assert drop["num_queues"] == 4, drop
assert len(drop["queues"]) == 4, drop["queues"]
assert len(dist["queues"]) == 4, dist["queues"]

drops = [int(q["drops"]) for q in drop["queues"]]
assert all(x > 0 for x in drops), drops
assert drop["totals"]["drops"] == sum(drops), (drop["totals"], drops)

queue_counts = [int(q["packets"]) for q in dist["queues"]]
total = sum(queue_counts)
assert total > 0, queue_counts
mean = total / 4.0
worst_bps = max(abs(x - mean) for x in queue_counts) * 10000.0 / mean
assert worst_bps <= threshold_bps, (queue_counts, worst_bps, threshold_bps)

cpus = [c for c in drop["cpus"] if int(c["cpu"]) < 4]
assert len(cpus) == 4, cpus
assert all(int(c["packets"]) > 0 for c in cpus), cpus
assert all(int(c["drops"]) > 0 for c in cpus), cpus

print(f"acceptance: queue_counts={queue_counts} "
      f"max_deviation_bps={worst_bps:.2f} threshold_bps={threshold_bps}")
print(f"acceptance: per_queue_drops={drops}")
print("acceptance: PASS")
PY
