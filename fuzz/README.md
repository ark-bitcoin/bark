# Bark Fuzzing

We use [honggfuzz](https://github.com/google/honggfuzz) with
[cargo-hfuzz](https://crates.io/crates/honggfuzz) to fuzz Bark's codebase.
The primary goal is to find inputs that cause panics, assertion failures, or
inconsistencies in VTXO encoding, preventing denial-of-service vulnerabilities
where malformed client data crashes the server.

## Prerequisites

### Using Nix (recommended)

All required dependencies (including `honggfuzz`, `binutils`, `libunwind`,
`gdb`, etc.) are provided by the project's Nix flake. Enter the dev shell
from the `bark/` root:

```bash
nix develop --extra-experimental-features "flakes nix-command"
```

> **Note:** The Nix package provides the `honggfuzz` binary but *not* the
> `cargo hfuzz` subcommand. The `fuzz.sh` script handles installing
> `cargo-hfuzz` automatically on first run.

### Platform support

Honggfuzz only runs on **Linux**. It does not work on macOS. If you are using
MacOS, the recommended workflow is to develop locally on macOS and run fuzzing
on a Linux server.

### glibc 2.40 workaround

On systems with glibc 2.40+, honggfuzz conflicts with `_FORTIFY_SOURCE`.
The `fuzz.sh` script applies the workaround automatically. If running
`cargo hfuzz` manually, prefix your command with:

```bash
NIX_HARDENING_ENABLE="" CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 $CFLAGS" cargo hfuzz run <target>
```

## Project structure

```bash
fuzz/
├── src/bin/            # Fuzz target source files
│   ├── vtxo_decode.rs
│   └── other targets go here
├── hfuzz_workspace/    # Honggfuzz runtime data & crash files
├── hfuzz_input/        # Optional seed corpora (per-target)
├── fuzz.sh             # Fuzzing orchestration script
├── debug.sh            # Crash analysis & debugging script
├── Cargo.toml
└── README.md
```

## Fuzzing targets

To help with fuzzing the targets, we crafted a `fuzz.sh` script to check the
needed dependencies and run each target sequentially by default, while allowing
arguments to be passed to costumize the control on fuzzing.

To run a single target:

```bash
./fuzz.sh <TARGET>
```

Run all targets sequentially (1 hour each by default):

```bash
./fuzz.sh
```

To check for possible arguments and usage:

```bash
./fuzz.sh --help
```

### Input corpus

If a directory `hfuzz_input/<target>/` exists, honggfuzz will use it as a
seed corpus. Adding real serialized VTXOs or other valid inputs here
significantly improves fuzzing effectiveness by giving the fuzzer a head
start toward interesting code paths. We currently hold a fuzz corpus on
our [bark-qa repo](https://gitlab.com/ark-bitcoin/bark-qa). Use the helper
script in it to pull the inputs to start fuzzing from a better corpus.

To run using the existing corpus, clone [bark-qa](https://gitlab.com/ark-bitcoin/bark-qa)
and run:

```bash
./fuzz.sh <target> --use-corpus <path_to_cloned_bark_qa>
```

Or combine it with other flags:

```bash
~/bark/fuzz$ ./fuzz.sh --use-corpus ~/../bark-qa -t 5000
```

## Debugging crashes

When honggfuzz finds a crash, it saves the triggering input under
`hfuzz_workspace/<target>/` with a filename like
`SIGABRT.PC.7fff....INSTR.mov____%eax,%ebp.fuzz`.

Use the debug script to analyze crashes:

```bash
./debug.sh <TARGET>
```

This will list available crash files, let you select one, and launch GDB
with the correct environment. Inside GDB, use `run` to reproduce the crash
and `bt` to get a backtrace.

To check available options:

```bash
./debug.sh --help
```

## Creating new fuzz targets

1. Duplicate an existing file in `fuzz/src/bin/`, e.g. `vtxo_decode.rs`,
   and rename it to match your new target (say `loud_barking.rs`).

2. In the new file, update the imports and modify the `do_test` function
   body to exercise the functionality you want to fuzz. Keep the function
   signature unchanged.

3. If your target depends on a crate not already listed in
   `fuzz/Cargo.toml`, add it as a dependency.

4. Verify the new target compiles (remember to check the needed dependencies
and use `./fuzz.sh` as needed):

   ```bash
   cargo hfuzz build
   ```

5. Run it:

   ```bash
   ./fuzz.sh loud_barking
   ```
