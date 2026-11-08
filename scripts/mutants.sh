#!/usr/bin/env bash
# Run cargo-mutants as N parallel shards, each with its own throwaway Postgres.
#
# Why shards and not `cargo mutants -j N`: all -j jobs share one environment, so
# they would share one database. Tests that sweep global tables, or a shared
# connection limit, can then fail a test in another job and record a false catch.
#
# Usage: scripts/mutants.sh [-n shards] [-m mem_cap] [-p base_port] [-o out_dir] [-- cargo-mutants args]
#   scripts/mutants.sh                               # whole repo, 4 shards, 20G cap
#   scripts/mutants.sh -n 2 -m 12G -- -f src/domain/crypto.rs
#
# Memory: every shard builds its own tree, so cargo's parallelism is divided
# between shards, and the run gets a cgroup cap. Any OOM inside the cap stops the
# whole run: a lone killed rustc or test would otherwise be recorded as a false
# unviable or caught mutant. After such a stop, rerun with a lower -n.
#
# Results land in <out_dir>/{caught,missed,timeout,unviable}.txt, with each shard's
# full output and run.log in <out_dir>/<k>/. Exits non-zero only if a shard itself
# failed (for example a red baseline), not because mutants were missed.
set -euo pipefail

orig_args=("$@")
shards=4
mem_cap=20G
base_port=5433
out=mutants-shards
pg_image=postgres:18-alpine

while getopts "n:m:p:o:h" opt; do
    case "$opt" in
        n) shards=$OPTARG ;;
        m) mem_cap=$OPTARG ;;
        p) base_port=$OPTARG ;;
        o) out=$OPTARG ;;
        h) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) exit 64 ;;
    esac
done
shift $((OPTIND - 1))

cd "$(dirname "$0")/.."

for tool in docker just; do
    command -v "$tool" >/dev/null || { echo "error: $tool is not installed" >&2; exit 1; }
done
cargo mutants --version >/dev/null 2>&1 || { echo "error: run: cargo install --locked cargo-mutants" >&2; exit 1; }

# Re-exec inside a memory-capped scope. Otherwise systemd-oomd treats the whole
# terminal as the offender and kills it along with everything else running there.
if [[ -z ${MUTANTS_SCOPED:-} ]]; then
    command -v systemd-run >/dev/null || { echo "error: systemd-run is required for the memory cap" >&2; exit 1; }
    exec systemd-run --user --scope --quiet --collect \
        -p MemoryMax="$mem_cap" -p MemorySwapMax=0 -p OOMPolicy=kill \
        env MUTANTS_SCOPED=1 "$0" "${orig_args[@]}"
fi
echo "Memory cap: $(cat "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.max") bytes"

pids=()
containers=()

cleanup() {
    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    if ((${#containers[@]})); then docker rm -f "${containers[@]}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'echo; echo "Interrupted, stopping shards..."; exit 130' INT TERM

# A hard kill skips the trap, so clear anything a previous run left behind.
stale=$(docker ps -aq --filter name=obscura-mutants-pg-)
if [[ -n $stale ]]; then
    # shellcheck disable=SC2086
    docker rm -f $stale >/dev/null
fi
rm -rf target/mutants-tmp

echo "Starting shared services..."
just services >/dev/null

echo "Starting $shards Postgres containers..."
for ((k = 0; k < shards; k++)); do
    name=obscura-mutants-pg-$k
    containers+=("$name")
    # tmpfs and fsync=off: this data is disposable and the tests are write-heavy.
    docker run -d --rm --name "$name" \
        -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=signal_server \
        -p "127.0.0.1:$((base_port + k)):5432" --tmpfs /var/lib/postgresql \
        "$pg_image" -c fsync=off -c max_connections=200 >/dev/null
done
for name in "${containers[@]}"; do
    # Over TCP on purpose: the image's init server only listens on the unix socket.
    until docker exec "$name" pg_isready -q -h 127.0.0.1 -U user -d signal_server; do sleep 1; done
done

# Each shard builds in its own copy of the tree. TMPDIR must be on real disk,
# because /tmp is often a small tmpfs. CARGO_PROFILE_DEV_DEBUG=0 shrinks and
# speeds up those builds. CARGO_BUILD_JOBS splits the cores between shards:
# left unset, every shard would run one compile or link job per core.
mkdir -p target/mutants-tmp
tmp=$PWD/target/mutants-tmp
build_jobs=$(($(nproc) / shards))
((build_jobs > 0)) || build_jobs=1

echo "Starting shards, logs in $out/<k>/run.log"
for ((k = 0; k < shards; k++)); do
    mkdir -p "$out/$k"
    TMPDIR=$tmp CARGO_PROFILE_DEV_DEBUG=0 CARGO_BUILD_JOBS=$build_jobs \
        OBSCURA_DATABASE_URL="postgres://user:password@localhost:$((base_port + k))/signal_server" \
        cargo mutants --shard "$k/$shards" --sharding round-robin -j 1 -o "$out/$k" "$@" \
        >"$out/$k/run.log" 2>&1 &
    pids+=($!)
done

count() { cat "$out"/*/mutants.out/"$1".txt 2>/dev/null | wc -l; }
progress() {
    printf '%s  caught=%s missed=%s timeout=%s unviable=%s\n' "$(date +%H:%M:%S)" \
        "$(count caught)" "$(count missed)" "$(count timeout)" "$(count unviable)"
}

running=$shards
while ((running > 0)); do
    sleep 30 &
    wait $! || true
    running=0
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then running=$((running + 1)); fi
    done
    echo "$(progress)  shards_running=$running"
done

# cargo-mutants exits 0 (all caught), 2 (missed) or 3 (timeouts) on a completed run.
failed=()
for ((k = 0; k < shards; k++)); do
    status=0
    wait "${pids[$k]}" || status=$?
    case "$status" in
        0 | 2 | 3) ;;
        *) failed+=("shard $k exited $status, see $out/$k/run.log") ;;
    esac
done
pids=()

for outcome in caught missed timeout unviable; do
    for ((k = 0; k < shards; k++)); do
        cat "$out/$k/mutants.out/$outcome.txt" 2>/dev/null || true
    done | sort >"$out/$outcome.txt"
done

echo
echo "Done: $(progress)"
echo "Missed mutants: $out/missed.txt"
if ((${#failed[@]})); then
    printf 'FAILED: %s\n' "${failed[@]}" >&2
    exit 1
fi
