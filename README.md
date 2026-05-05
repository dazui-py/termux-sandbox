# termux-sandbox

`termux-sandbox` is an experimental PRoot-based sandbox manager for Termux.

It creates isolated Termux-like environments where each sandbox has its own:

- `HOME`
- `PREFIX`
- `TMPDIR`
- package database
- shell configuration
- installed binaries
- project workspace
- logs
- policies and grants

The real Termux installation stays as the host. Each sandbox gets its own filesystem under:

`~/.termux-sandbox/boxes/<name>/rootfs/`
Inside the sandbox, programs still see the normal Termux paths:
`
/data/data/com.termux/files/home
/data/data/com.termux/files/usr
`

But those paths belong to the sandbox rootfs, not to the real Termux installation.

DISCLAIMER: This project is usable for testing, but it is not stable yet. Expect bugs, missing features and breaking changes.
