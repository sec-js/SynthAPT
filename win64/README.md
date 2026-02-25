If you want to build the shellcode individually you'll need to do the following. This usually isn't necessary unless you want to have different shellcode builds with different features (i.e. if size is a concern).

1. Nightly Rust
2. Binutils
3. Cargo Make

```bash
rustup toolchain install nightly
apt install binutils-mingw-w64-x86-64
cargo install cargo-make
```

Build with cargo make:

```bash
cargo make build
```

The shellcode will be in `../out/shellcode.bin`.