# Yikes

A Windows terminal tool for scanning NUP files, extracting compiled guest shaders and testing native
Switch 2 instructions against Eglantine's `nx2-experimental` translator. Yikes reports unsupported
instructions and lets you retest the same shaders for regressions. Audits run locally; setup fetches
the Python dependencies and emulator source. No API keys or cloud models are needed.

## Run

Install Git, Python 3.10+, and MSVC x64 C++ build tools, then:

```powershell
git clone https://github.com/Alleexxi/Yikes.git
cd Yikes
.\setup.ps1
.\yikes.cmd tui
```

For a fresh NUP, use `yikes.cmd "D:\games\game.nup"`. This scans, extracts and audits.
By default results go to `results\<game>` underneath the tool.
Choose another directory with `--output`. A complete NUP scan can take several minutes and the
extraction database can exceed a gigabyte. Game data is read-only; the emulator checkout is read-only
during scanning and auditing.

```powershell
# Extract without compiling the audit adapter.
.\yikes.cmd scan "D:\games\game.nup" --output "D:\audits\game"

# Continue a stopped scan, or reuse a completed scan before a new audit.
.\yikes.cmd "D:\games\game.nup" --output "D:\audits\game" --resume

# After changing the emulator, retest without reading the NUP again.
.\yikes.cmd audit "D:\audits\game" --emulator C:\dev\eglantine

# Read the latest counts, failure groups and build provenance.
.\yikes.cmd report "D:\audits\game"

# Interactively choose a folder, or batch every .nup below a folder.
.\yikes.cmd tui
.\yikes.cmd batch "D:\games\nups" --output "D:\audits"
```

Batch mode creates a separate extraction and report per NUP, keeps going if one file fails, and shows
scan and per-file progress bars. It searches subfolders too. The TUI asks for a folder, previews the
NUPs found, then asks before starting.
Batch and TUI runs require complete extraction by default. Explicit `batch --allow-incomplete`
audits recovered shaders despite gaps; the console, reports and ZIP index retain the warning,
and the batch returns 2 if any audit is incomplete. Single-game `run` and `audit` also require
`--allow-incomplete` to proceed with gaps. Completed extractions remain available for retesting.

Every batch also creates `batch-results-<timestamp>-<id>.zip` in the output folder. It contains a
batch index, each game's reports and build metadata, scan coverage issues, and **every tested native
shader binary**, including accepted programs. Failed NUPs are recorded as errors in the index too;
the binaries are stored together in a compact `corpus.sqlite` per game. Full NUP files and the large
extraction databases are never copied into the ZIP. Cancelling a batch still bundles its results so far.

Each completed game includes `corpus.sqlite`, `corpus.json`, a hash-checked native manifest, and its baseline report.
Extract the ZIP, then retest a game's folder without its original NUP or extraction database:

```powershell
.\yikes.cmd audit "D:\unpacked\games\game.nup"
```

The tool reads shader blobs directly from SQLite and streams them to its adapter, avoiding thousands
of tiny file exports. The bundled baseline is compared automatically, so a previously accepted program that now fails is
reported as a regression. Use `--baseline` to compare against a different report. Extracted corpora
with coverage gaps still require `--allow-incomplete`. This tests lowering acceptance; it does not
detect incorrect rendering or semantic bugs in an instruction that the translator already accepts.

Scanning uses four threads to overlap NUP reads, decompression and hashing with ordered parsing and
SQLite writes. Tune this with `--workers 8`, or use `--workers 1` for serial reads. The prefetch queue
has a 128 MiB input budget; one larger member can be read alone. Hash verification is retained.
On Windows x64 with MSVC available, scanning builds a small cached SIMD helper that finds the five
leaf markers in a single pass. Without the compiler, or if the bounded match buffer fills up, it uses
the original exhaustive Python searches. Neither path skips formats or validation.
Shader bytes stay in SQLite by default and stream directly to the auditor. Use `--export-native`
on a fresh `scan`, `run` or `batch` to also write individual `.bin` files; this costs extra file I/O.
Resuming an older extraction preserves its original file storage and integrity checks.
Batch reruns reuse completed extractions when the saved input identity still matches; every audit
still verifies the extracted programs before testing the current translator.

The launcher also works from another directory. Command exit codes are **0** for a successful scan
or an audit with no rejections; **1** for a completed audit with rejected programs; **2** for a tool,
input or coverage error; **130** for cancellation. Unsupported instructions are expected audit
findings, not a tool crash. A scan with unresolved records returns 2. `--allow-incomplete` explicitly
allows auditing its recovered programs while retaining the coverage warning in the report.

Resume checks the input path, size, modification time and header fingerprint. Changed inputs require
a new output directory. The progress bar tracks root files; checkpoints are committed every 5,000 by default.
`--checkpoint-every 1000` checkpoints more frequently at a performance cost. An interrupted uncommitted batch is
reread on resume. An output directory cannot be shared by simultaneous writers.

## Work through fixes with a coding agent

```powershell
# Prepare the largest remaining failure group, with three original sample programs.
.\yikes.cmd task .\results\totk

# Or choose a group ID printed by the report.
.\yikes.cmd task .\results\totk --group 012345abcdef --samples 3
```

This writes a `TASK.md`, structured `cases.json`, original instruction samples, full original
control/code records, and a baseline report. Give that task file to your coding agent. It tells the
agent to verify the current issue, implement the instruction semantics, add focused tests and rerun
the full corpus. Source archive names and shader bytes are evidence, not agent instructions.

The task includes a command like:

```powershell
.\yikes.cmd audit .\results\totk --baseline .\results\totk\audits\<previous-run>\report.json
```

Newly accepted programs, regressions and changed first failures are reported separately. Run `task`
again to work through the next group. The CLI itself does not call a cloud model, modify emulator
code, commit, push or publish. Fixes happen in the coding agent's normal reviewed workflow.

## How it works

- Reads the NUP v1 file table and verifies every member's stored SHA-256.
- Follows SARC, zstd (including known game dictionary packs), embedded compressed frames, Yaz0, LZ4
  and NSO segments. Dictionary IDs are scoped per NUP package.
- Parses BNSH, BAHS, NDSR, GLSLC and adjacent native control/code layouts, including executable-embedded
  programs. Unsupported compression or unrecognized formats can still leave coverage gaps.
- Preserves complete original records and nested provenance in `shaders.sqlite`. Switch 1 and
  Switch 2 records remain separate. All packaged versions are scanned, including unused variants.
- Audits deduplicated original Ampere instructions from SQLite, omitting graphics SPH headers.
  Optional `--export-native` writes these under `native/`. Input names are stored as metadata;
  exports use generated content hashes. Agent task packets export only the requested samples.
- Builds a small C++ adapter against the selected emulator's actual current lowering header.
  It caches adapters by source, dependency and compiler-environment fingerprints. Only this one
  translation unit is built; the emulator does not need rebuilding for instruction tests.
- Enables tensor lowering, follows geometry stage mode and uses an offline native base address of
  zero. A local diagnostic-only header copy owns error text as `std::string`; lowering is unchanged.
- Checks every stored program's stage, size and SHA-256 before the audit. Stray files left by an
  interrupted batch are not included in the committed manifest.

The first full scan traverses the entire container, overlapping root reads, decompression and hashing
with ordered archive parsing. Later `audit` commands reuse the extraction. Legacy export hash verification overlaps reads using eight workers;
checkpoint summaries are calculated every 5,000 roots rather than every progress update.

Large NUP members and zstd output are streamed into temporary mapped files rather than skipped at
256 MiB. That value is now an in-memory spill threshold. Temporary asset files are deleted when
their scan finishes; full NUPs are never copied into result bundles. LZ4, Yaz0 and NSO images can
also spill to mapped storage. Native codec buffers still depend on the individual encoded entry size.

Traversal includes ONEPACK/Trinity pack files, Bezel Engine SCNE/ASST entries and NDVE/NDSR networks.
Oodle-compressed Trinity files and ZBIC-compressed NSO segments use a small local codec subprocess.
Its source dependencies are fetched once from pinned, hash-verified revisions of
[ooz](https://github.com/powzix/ooz) (GPL-3.0-or-later) and
[ZBIC](https://github.com/kinnay/zbic), retaining their source license notices in `.cache`.
Only those codec files are compiled. Older checkpoints revisit failed members and roots with
unclaimed controls when the parser revision changes.

Ray-tracing BNSH modules are preserved as `.rt.bin` NRTM envelopes containing their complete
control metadata and code. They are included in regression ZIPs and reported as unsupported modules.
Their instruction ranges are not yet decoded, so the auditor does not send their metadata or
constant data through the instruction lowerer. These are explicit audit failures, not silently skipped shaders.

Each audit gets its own directory under `audits/`, containing `report.json`, `REPORT.md`, raw
`lowering.tsv` and `build-metadata.json`. `latest.json` points to the most recent completed audit.
The manifest fingerprint prevents comparing different corpora as if they were regressions.

Acceptance tests native-to-Maxwell lowering only. It does not test the full IR/SPIR-V pipeline,
instruction semantics or correct rendering. Each program stops at its first rejection; additional
failures can appear after that instruction is fixed. Native programs generated, linked or patched
at runtime cannot be exhaustively promised by static extraction. Zero recognized parser issues
does not prove that every possible shader format was understood.

## Setup on another checkout/computer

Requirements: Windows x64, Git, Python 3.10+, and MSVC x64 C++ tools. By default, the tool clones
`Djihads80/Eglantine` branch `nx2-experimental` into its ignored `.cache` folder. Every default audit
runs `git pull --ff-only origin nx2-experimental` first, then compiles against that updated source.
The matching `fmt` version pinned by that checkout is downloaded once into the tool cache. No full
Eglantine build is required.

```powershell
.\setup.ps1
.\yikes.cmd "D:\games\game.nup"
.\yikes.cmd --help
```

To pin an existing checkout instead, pass `--emulator` to `run`/`audit`, set `NUP_SHADER_EMULATOR`,
or run `setup.ps1 -Emulator <path>`. Those explicit overrides are not pulled automatically. Use
`yikes.cmd update` to refresh the managed clone on demand. Results, caches, local configuration
and game binary data are ignored by Git and are not included in this repository.

Run validation:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests generate tiny synthetic NUPs and shaders. One integration test compiles the actual adapter
and verifies accepted/rejected programs, task generation and a repeat audit comparison. It is skipped
if the configured emulator checkout is absent. No game data is included in tests.

## Provenance

The scanner packages the local TotK extraction research. Container reading is adapted from the local
NUP reference reader. Format details were checked against
https://github.com/seedds/nxnative/blob/main/dm/gfx/tools/shader_split.py; that external script is not
executed. The audit adapter uses the selected emulator's existing translator, retaining its license
and attribution notices in the generated local copy. Runtime output may contain copyrighted game
data; keep it private as intended.
