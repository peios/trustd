# trustd

Peios certificate-store composition and the trust command.
The public client library is `libtrust.so.1`, with the safe Rust wrapper
`trust-client`.

- [Build and validate](docs/building.md).
- [User and developer documentation](docs/learn/1--peios.shelf/peios.product).
- [Command and library manuals](docs/man).

Use pekit to build and test trustd. Packages and builds with the native
Peios toolchain are not yet built with pekit; a Linux development build is
not a native release qualification.
