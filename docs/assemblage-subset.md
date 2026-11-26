# Assemblage add-on

`baseline sync` adds the files pinned in
`src/rulezet_validation/baseline/assemblage.json` to the default baseline.
Downloaded archives and binaries remain under ignored `data/` directories.

## Contents

| part | files | source |
|---|---|---|
| `pe/` | 2,500 | `Assemblage_PE` `binaries.tar.xz`: Windows PE built with MSVC v140 to v143, x86 and x64, Od/O1/O2/Ox |
| `elf/` | 1,500 | `Assemblage_LinuxELF` June 2024 revision `binaries.tar.xz.partaa`: x86-64 C/C++ built with gcc and clang, O0 to O3 and Oz |
| `rust/` | 200 | `assemblage-rust` per-repository archives: x86-64 Rust built with llvm, gcc and cranelift backends, O0 to Oz |

All three parts keep only permissive licenses (MIT, Apache-2.0, BSD, ISC,
Zlib, BSL-1.0, CC0, Unlicense) and at most three files per source repository.
Files are 20 MB or smaller. CMake feature probes (`CMake*`, `*.bin`) and bare
`a.out` test programs are skipped, because thousands of near-identical stubs
would crowd out real programs.

Assemblage contains no ARM, MIPS or other non-x86 builds. Architecture
coverage comes from `baseline/ports.json` (Debian ports) and
`baseline/openwrt.json` (OpenWrt ARM).

## Reading the archives

The PE and C/C++ ELF releases are each one archive of 30 GB or more, with no
per-file access. The script streams each archive from the start and stops once
it has selected enough files. The lock records how many compressed bytes that
took (`prefix_bytes`) and their SHA-256. `baseline sync` streams the same
archive again and stops when it has every pinned member. Each file is checked
against its pinned SHA-256.

The PE and C/C++ ELF parts are therefore archive prefixes, not uniform samples
of the whole release.

Licenses come from Assemblage's own per-binary indexes, joined on file SHA-256:

- PE: `binaries.csv` at `Assemblage_PE` revision `12803410d3a6`.
- ELF: `linux.sqlite.tar.xz` at `Assemblage_LinuxELF` revision `efbaa11cd2cc`.
  This revision also holds the archive part the ELF files are read from, so the
  index and archive describe the same build. The current 2026 archive mixes in
  builds this index does not cover.

The Rust release provides one archive per repository. The script downloads
only the selected repositories, and the lock pins each archive's SHA-256.

## Regenerating

```sh
PYTHONPATH=src python3 -m rulezet_validation.baseline_assemblage --pe 2500 --elf 1500 --rust 200
```

Regeneration changes the lock only if upstream content or the selection code
changes. Ordinary `baseline sync` uses the committed lock. The source archives
are not committed or served to users. Assemblage notes that binaries keep
their source repositories' licenses; its tool's MIT license does not apply to
the binaries.
