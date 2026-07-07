#!/usr/bin/env bash
set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)
FUZZ_DIR="$REPO_DIR/fuzz"

# Default configuration (can be overridden by env vars or flags)
RUN_TIME="${RUN_TIME:-3600}"
EXIT_ON_CRASH="${EXIT_ON_CRASH:-1}"
VERBOSE=0
LOOP=0
DAEMON=0
USE_CORPUS=""
JOBS=""
MINIMIZE=0
REPLAY=0
T_GIVEN=0

usage() {
    cat <<EOF
Bark Fuzzing Script

Run honggfuzz against Bark fuzz targets. Requires honggfuzz dependencies
to be installed. If using nix, run the following from bark/:
    nix develop --extra-experimental-features "flakes nix-command"

USAGE:
    $(basename "$0") [OPTIONS] [TARGET]

ARGS:
    [TARGET]    Specific fuzz target to run (e.g., vtxo_decode)
                If omitted, runs all targets sequentially

OPTIONS:
    -h, --help              Show this help message
    -t, --time <SECONDS>    Run time per target in seconds (default: 3600)
    -c, --continue          Continue fuzzing after crash (default: exit on crash)
    -v, --verbose           Enable verbose output
    -l, --loop              Run continuously until killed (restarts after --time)
    -d, --daemon            Run in background, prints PID and exits
    -j, --jobs <N>          Number of CPUs/threads to use (default: honggfuzz default)
    --minimize              Minimize corpus (honggfuzz -M). Panic-preserving:
                            the same pass replays every input through the harness,
                            so contained-panic reproducers are captured and
                            re-injected after -M (which is otherwise blind to them
                            and could prune a reproducer that adds no new coverage).
    --replay                Re-run the accumulated corpus under the current build
                            to flush latent panics (incl. the debug_assert!s the
                            release profile now compiles in). Short per-target run,
                            does not exit on crash, and logs + summarizes the
                            contained (unwind-isolated) panics it hits.
    --use-corpus <PATH>     Use corpus from a cloned bark-qa repo at PATH

ENVIRONMENT VARIABLES:
    RUN_TIME                Same as --time (flag takes precedence)
    EXIT_ON_CRASH           Set to 0 for --continue behavior (flag takes precedence)

EXAMPLES:
    $(basename "$0")                        # Fuzz all targets for 1 hour each
    $(basename "$0") vtxo_decode            # Fuzz vtxo_decode for 1 hour
    $(basename "$0") -t 600 vtxo_decode     # Fuzz vtxo_decode for 10 minutes
    $(basename "$0") -c -t 1800             # Fuzz all targets, 30 min each, don't stop on crash
    $(basename "$0") --loop                 # Fuzz all targets on loop (1h each) until killed
    $(basename "$0") vtxo_decode -c --loop  # Fuzz target indefinitely, don't exit on crash
    $(basename "$0") vtxo_decode --loop     # Fuzz target indefinitely, exit on crash
    $(basename "$0") --daemon               # Run in background, returns PID
    $(basename "$0") vtxo_decode --use-corpus ~/bark-qa  # Fuzz with bark-qa corpus
    RUN_TIME=300 $(basename "$0")           # Fuzz all targets for 5 minutes each

NOTES:
    - honggfuzz does not currently support macOS
    - Input corpus files can be placed in hfuzz_input/<target>/input
    - To run using an existing corpus, clone bark-qa and use --use-corpus:
        git clone https://gitlab.com/ark-bitcoin/bark-qa
        $(basename "$0") <target> --use-corpus <path_to_cloned_bark_qa>
    - Crash artifacts are saved to hfuzz_workspace/<target>/
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -t|--time)
            RUN_TIME="$2"
            T_GIVEN=1
            shift 2
            ;;
        -c|--continue)
            EXIT_ON_CRASH=0
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -l|--loop)
            LOOP=1
            shift
            ;;
        -d|--daemon)
            DAEMON=1
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --minimize)
            MINIMIZE=1
            shift
            ;;
        --replay)
            REPLAY=1
            shift
            ;;
        --use-corpus)
            USE_CORPUS="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -n "${TARGET:-}" ]; then
                echo "Error: Unexpected argument '$1' (target already set to '$TARGET')" >&2
                usage >&2
                exit 1
            fi
            TARGET="$1"
            shift
            ;;
    esac
done

# Validate --use-corpus path if provided
if [ -n "$USE_CORPUS" ]; then
    if [ ! -d "$USE_CORPUS" ]; then
        echo "Error: Corpus path '$USE_CORPUS' does not exist or is not a directory" >&2
        exit 1
    fi
    # Resolve to absolute path
    USE_CORPUS=$(cd "$USE_CORPUS" && pwd)
fi

trap 'exit 130' INT

# Replay mode: re-run the accumulated corpus under the current build to surface
# latent contained panics (honggfuzz replays every corpus input at startup, so a
# short run suffices). Don't abort on crash, and default to a short per-target run.
if [ "$REPLAY" = "1" ]; then
    EXIT_ON_CRASH=0
    if [ "$T_GIVEN" = "0" ]; then
        RUN_TIME=20
    fi
fi

# Summarize the contained panics the harness wrote to $HFUZZ_CONTAINED_FILE
# during a replay run: a total count plus a frequency-ranked list of source
# locations. Emits CONTAINED-SUMMARY / CONTAINED-LOC lines for the daily report.
summarize_contained() {
    local target="$1" cfile="$2"
    local total locs unique
    # Only count/parse well-formed sentinel lines ("CONTAINED\t<file:line:col>: msg"),
    # so any torn write is dropped rather than mis-parsed into a bogus location.
    if [ -f "$cfile" ]; then
        total=$(grep -cE '^CONTAINED'$'\t' "$cfile" 2>/dev/null) || total=0
    else
        total=0
    fi
    echo "=== Contained-panic summary: $target ==="
    if [ "${total:-0}" -gt 0 ]; then
        # A counted line may still lack a parseable location (e.g. a panic with
        # a non-string payload), so these can come up empty under pipefail.
        locs=$(grep -E '^CONTAINED'$'\t' "$cfile" \
            | grep -oE '[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+' \
            | sort | uniq -c | sort -rn) || locs=""
        unique=$(printf '%s\n' "$locs" | grep -c .) || unique=0
        echo "CONTAINED-SUMMARY target=$target total=$total unique=$unique"
        printf '%s\n' "$locs" | while read -r count loc; do
            if [ -n "$loc" ]; then
                echo "CONTAINED-LOC $target $count $loc"
            fi
        done
    else
        echo "CONTAINED-SUMMARY target=$target total=0 unique=0"
    fi
    echo "=== End contained-panic summary: $target ==="
}

run_fuzzing() {
    # Enable command tracing if verbose
    if [ "$VERBOSE" = "1" ]; then
        set -x
    fi

    # Workaround for glibc 2.40+ fortify source conflicts with honggfuzz
    export NIX_HARDENING_ENABLE=""
    export CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ${CFLAGS:-}"

    # sccache doesn't work with honggfuzz's sanitizer flags; bypass it entirely
    unset RUSTC_WRAPPER
    unset RUSTC_WORKSPACE_WRAPPER

    # Replay mode surfaces contained (unwind-isolated) panics — including the
    # debug_assert!s now compiled into the release profile — which the harness
    # otherwise only counts. Kept off for normal campaigns: a contained panic
    # can fire millions of times and would flood the log (see fuzz/src/lib.rs).
    if [ "$REPLAY" = "1" ]; then
        export HFUZZ_LOG_CONTAINED=1
    fi

    echo "cargo $(cargo --version)"
    echo "rustc $(rustc --version)"

    # Ensure cargo-hfuzz is installed (nix provides honggfuzz but not the cargo subcommand)
    if ! cargo hfuzz version &>/dev/null; then
        echo "Installing cargo-hfuzz..."
        cargo install --force honggfuzz --no-default-features
    fi

    # Get all fuzz targets from src/bin/
    get_targets() {
        find "$FUZZ_DIR/src/bin" -name '*.rs' -exec basename {} .rs \; 2>/dev/null | sort
    }

    if [ -n "${TARGET:-}" ]; then
        targetFiles="$TARGET"
    else
        targetFiles=$(get_targets)
    fi

    if [ -z "$targetFiles" ]; then
        echo "Error: No fuzz targets found in $FUZZ_DIR/src/bin/" >&2
        exit 1
    fi

    while true; do
        for target in $targetFiles; do
            echo "=== Fuzzing target: $target ==="

            # Build HFUZZ_RUN_ARGS
            HFUZZ_RUN_ARGS="--run_time $RUN_TIME"

            if [ "$EXIT_ON_CRASH" = "1" ]; then
                HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS --exit_upon_crash"
            fi

            if [ "$VERBOSE" = "1" ]; then
                HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -v"
            fi

            if [ -n "$JOBS" ]; then
                HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -n $JOBS"
            fi

            if [ "$MINIMIZE" = "1" ]; then
                HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -M"
            fi

            # Determine input corpus path
            if [ -n "$USE_CORPUS" ]; then
                corpus_dir="$USE_CORPUS/fuzz_corpora/$target/input"
                if [ -d "$corpus_dir" ]; then
                    HFUZZ_RUN_ARGS="$HFUZZ_RUN_ARGS -f $corpus_dir"
                    echo "Using corpus from: $corpus_dir"
                else
                    echo "Warning: No corpus found for target '$target' at $corpus_dir" >&2
                fi
            elif [ -d "$FUZZ_DIR/hfuzz_input/$target" ]; then
                # Seed honggfuzz's gitignored workspace corpus from the tracked,
                # read-only seed dir. Do NOT point honggfuzz (-f) at hfuzz_input:
                # it owns its -f dir and a `--minimize` (-M) pass rewrites it to
                # hash-named units, deleting the committed seeds.
                ws_input="$FUZZ_DIR/hfuzz_workspace/$target/input"
                mkdir -p "$ws_input"
                cp -n "$FUZZ_DIR/hfuzz_input/$target/input/"* "$ws_input/" 2>/dev/null || true
            fi

            # Panic-preserving minimize: honggfuzz -M is blind to contained panics
            # and can prune a reproducer that adds no coverage. Since -M executes
            # every input (a replay), arm the harness's input sink
            # (HFUZZ_CONTAINED_DIR) at a holdout dir outside the corpus and
            # re-inject the saved reproducers afterwards.
            if [ "$MINIMIZE" = "1" ]; then
                if [ -n "$USE_CORPUS" ]; then
                    minimize_corpus_dir="$USE_CORPUS/fuzz_corpora/$target/input"
                else
                    minimize_corpus_dir="$FUZZ_DIR/hfuzz_workspace/$target/input"
                fi
                holdout_dir="$FUZZ_DIR/hfuzz_workspace/$target/minimize_holdout"
                rm -rf "$holdout_dir"
                mkdir -p "$holdout_dir"
                export HFUZZ_CONTAINED_DIR="$holdout_dir"
            fi

            export HFUZZ_RUN_ARGS
            cd "$FUZZ_DIR"

            # In replay mode, point the harness's contained-panic file sink at a
            # fresh per-target file, run, then summarize from it. honggfuzz
            # swallows the child's stderr, so the file is the only reliable
            # channel for contained panics (see fuzz/src/lib.rs).
            if [ "$REPLAY" = "1" ]; then
                contained_file=$(mktemp)
                export HFUZZ_CONTAINED_FILE="$contained_file"
                set +e
                cargo hfuzz run "$target"
                run_status=$?
                set -e
                unset HFUZZ_CONTAINED_FILE
                summarize_contained "$target" "$contained_file"
                rm -f "$contained_file"
            else
                set +e
                cargo hfuzz run "$target"
                run_status=$?
                set -e
            fi

            if [ "$run_status" -ne 0 ]; then
                if [ "$EXIT_ON_CRASH" = "1" ]; then
                    echo "=== Crash detected in $target, exiting ==="
                    exit 1
                fi
            fi

            # Re-inject the reproducers held out during the -M pass so minimize is
            # panic-preserving. cp -n keeps honggfuzz's own survivors; idempotent.
            if [ "$MINIMIZE" = "1" ]; then
                unset HFUZZ_CONTAINED_DIR
                saved=$(find "$holdout_dir" -type f 2>/dev/null | wc -l)
                if [ "$saved" -gt 0 ] && [ -d "$minimize_corpus_dir" ]; then
                    cp -n "$holdout_dir"/* "$minimize_corpus_dir"/ 2>/dev/null || true
                    echo "=== Panic-preserving minimize: re-injected $saved contained-panic reproducer(s) into $minimize_corpus_dir ==="
                    grep -rl . "$holdout_dir" 2>/dev/null | xargs -r -n1 basename | sed 's/^/    - /' || true
                else
                    echo "=== Panic-preserving minimize: no contained panics observed this pass; nothing to re-inject ==="
                fi
            fi

            echo
        done

        if [ "$LOOP" = "0" ]; then
            break
        fi

        echo "=== Loop complete, restarting fuzzing cycle ==="
    done

    echo "=== Fuzzing complete ==="
}

# Daemon mode: fork to background
if [ "$DAEMON" = "1" ]; then
    run_fuzzing &>/dev/null &
    pid=$!
    echo "$pid"
    exit 0
fi

run_fuzzing
