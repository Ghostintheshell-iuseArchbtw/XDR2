# XDR2

Experimental endpoint detection and response stack.

## Build & Test

```powershell
# Format code
cargo fmt --all

# Lint
cargo clippy --all-targets --all-features -D warnings

# Run tests
cargo test --all
```

The Rust toolchain is pinned via `rust-toolchain.toml` to ensure
reproducible builds.
