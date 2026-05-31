# Common harness state. Source this; do not execute.
# All paths absolute so scripts work from any CWD.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/fixtures"
RESULTS="$ROOT/results"
CORPUS="${CORPUS:-$FIXTURES/corpus-5000.scale}"
CORPUS_DEEP="$FIXTURES/corpus-50000.scale"
ORACLE="${ORACLE:-$FIXTURES/canonical-hashes.txt}"
ORACLE_DEEP="$FIXTURES/canonical-hashes-deep.txt"

WORKTREE="$(cd "$ROOT/../.." && pwd)"
# Use the live lab's canonical-cache binary as the test subject.
# Same binary the running validators use — both DB backends compiled in,
# wasmtime-backend feature enabled (the worktree's fresh build is not, by
# Rostro default — see substrate/client/executor/Cargo.toml). Override via
# GEMINI_NODE=... if you want to test a different binary.
GEMINI_NODE="${GEMINI_NODE:-/home/coder/Rostro/.star/alice/canonical-cache/gemini-node}"

# The `star` chain-spec genesis depends on ROSTRO_CANONICAL_GEMINI_NODE_HASH
# (blake2_256 of the gemini-node binary at bootstrap). Without the matching
# hash, every block-1 import fails with "unknown parent" because genesis
# storage differs. Compute it from the bootstrap binary once and export it
# for all subcommands in this lib.
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="${ROSTRO_CANONICAL_GEMINI_NODE_HASH:-$(
  python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$GEMINI_NODE"
)}"

# Disk-side state. /var/lib/* so survival across reboots is intentional.
BACKING_IMG="/var/lib/paritydb-torture/backing.img"
BACKING_SIZE_GB=10
DM_NAME="paritydb_flakey"
DM_DEV="/dev/mapper/$DM_NAME"
MOUNT="/mnt/paritydb-torture"

LOOP_DEV_FILE="/var/lib/paritydb-torture/loop.dev"

# 10GB / 512 bytes-per-sector
SECTORS=$(( BACKING_SIZE_GB * 1024 * 1024 * 1024 / 512 ))

# Pass-through, drop-writes, and corrupt-bio-byte dm-flakey tables. Loop dev varies.
PASSTHRU_TABLE_FMT="0 $SECTORS flakey %s 0 86400 0"
DROP_WRITES_TABLE_FMT="0 $SECTORS flakey %s 0 0 86400 1 drop_writes"
# corrupt_bio_byte <Nth_byte> <direction> <value> <flags>:
# corrupt byte 1 of every write to 0xff. Feature count is 5 tokens.
CORRUPT_TABLE_FMT="0 $SECTORS flakey %s 0 0 86400 5 corrupt_bio_byte 1 w 255 0"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

require_root_tools() {
  for t in losetup dmsetup mkfs.ext4 systemd-run; do
    command -v "$t" >/dev/null || die "missing tool: $t"
  done
  sudo -n true 2>/dev/null || die "sudo must be passwordless"
}

current_loop_dev() {
  [ -r "$LOOP_DEV_FILE" ] || die "loop dev not registered — run setup-flakey-dev.sh first"
  cat "$LOOP_DEV_FILE"
}
