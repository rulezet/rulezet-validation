# Rust implementation

All Rust crates, Cargo manifests, and Rust source code for this project live in
this directory. Keeping the Rust implementation here gives Cargo an isolated
workspace while leaving the Python package under `src/rulezet_validation/`.

New Rust crates should be created as children of this directory. Do not place
`Cargo.toml`, `Cargo.lock`, or `*.rs` files elsewhere in the repository.
