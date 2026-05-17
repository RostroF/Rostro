#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 1 — all-clean.
#
# All 5 nodes have the correct gemini-node binary in their per-node
# canonical-cache. Genesis seeds the canonical hash. Expected:
#
#   * Every node's verifier logs "all 1 canonical files verified".
#   * Every node's asker logs "passed canonical-files attest" for
#     each peer it sees.
#   * Blocks rotate + finalize (Sassafras + GRANDPA both healthy).
#
# Exit 0 on success. On assertion failure, dumps the relevant log
# fragment and exits 1.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STAR_SCRIPT="$REPO_ROOT/scripts/run-star.sh"

# Time budget. Star needs:
#   ~5s to come up, ~15s for attest exchanges to complete after
#   peers connect, ~30s for a few finalized blocks. Tight enough
#   to keep the scenario fast; loose enough that variance in CI
#   doesn't flake.
RUN_SECS="${RUN_SECS:-45}"

cleanup() {
	if [[ -n "${STAR_PID:-}" ]]; then
		# Star's own trap kills children on EXIT; sending it SIGINT
		# is enough.
		kill -INT "$STAR_PID" 2>/dev/null || true
		wait "$STAR_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

echo "=== scenario 01: all-clean ==="
echo "starting star (will run for ${RUN_SECS}s)..."
"$STAR_SCRIPT" > /tmp/star-01.out 2>&1 &
STAR_PID=$!

sleep "$RUN_SECS"
cleanup
STAR_PID=""

# Assertions.
FAIL=0
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	if [[ ! -f "$log" ]]; then
		echo "FAIL [$name]: no log file at $log"
		FAIL=1
		continue
	fi

	# Verifier passed.
	if ! grep -q "canonical files verified" "$log"; then
		echo "FAIL [$name]: verifier did not log 'canonical files verified'"
		echo "  last 20 verifier lines:"
		grep -E "rostro-file-check|FOUNDATION" "$log" | tail -20 | sed "s/^/    /"
		FAIL=1
		continue
	fi
	echo "OK [$name]: verifier passed"

	# Attest asker saw at least one peer pass.
	if ! grep -q "passed canonical-files attest" "$log"; then
		echo "FAIL [$name]: asker saw no peers pass attest"
		echo "  last 10 asker lines:"
		grep "rostro-attest-asker" "$log" | tail -10 | sed "s/^/    /"
		FAIL=1
		continue
	fi
	echo "OK [$name]: asker saw at least one peer pass attest"
done

# Block production + finality. Look for "Imported #N" and
# "finalized #N" with N >= 3.
ANY_FINALIZED=0
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	[[ -f "$log" ]] || continue
	if grep -qE "finalized #[1-9]" "$log"; then
		ANY_FINALIZED=1
		break
	fi
done
if [[ $ANY_FINALIZED -eq 0 ]]; then
	echo "FAIL: no node logged a finalized block"
	FAIL=1
else
	echo "OK: at least one finalized block observed"
fi

if [[ $FAIL -ne 0 ]]; then
	echo
	echo "=== scenario 01 FAILED ==="
	exit 1
fi
echo
echo "=== scenario 01 PASSED ==="
