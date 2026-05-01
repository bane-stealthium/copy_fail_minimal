# copy_fail_minimal

Minimal C proof-of-concept for CVE-2026-31431 ("Copy Fail").

## How it works

A logic flaw in the `authencesn` component of the Linux kernel crypto API allows an unprivileged user to write 4 bytes at a time into the page cache of any file they can open for reading - including SUID binaries. No race conditions, no kernel offsets, no timing windows required.

The exploit chain:

1. Open an AF_ALG AEAD socket bound to `authencesn(hmac(sha256),cbc(aes))`.
2. `sendmsg()` with `MSG_MORE` queues the payload chunk for the kernel crypto operation.
3. `splice()` the target file into the pipe, then splice the pipe into the socket - this triggers the logic bug, writing the payload bytes into the file's page cache without a write permission check.
4. Repeat in 4-byte chunks across the full payload length.
5. Execute the now-patched SUID binary.

The injected payload (`payload.c`) is a dependency-free ELF that calls `setuid(0)` + `setgid(0)` + `execve("/bin/sh")` via raw syscalls with no libc.

## Requirements

- Linux kernel ≥ 2017 releases, unpatched before mainline commit `a664bf3d603d`
- `CONFIG_CRYPTO_USER_API_AEAD=y` (default on most distros)
- Read access to the target SUID binary

## Build

```
make
```

Builds `payload.elf` from `payload.c`, embeds it as `payload.h`, then compiles the exploit. Both binaries are fully static with no libc dependency.

## Usage

```
make run
```

Patches `/usr/bin/su` in the page cache and executes it. The patch is not written to disk - a reboot or `drop_caches` restores the original binary.

```
make drop_caches   # restore without rebooting (requires sudo)
```

## Files

| File | Description |
|------|-------------|
| `copy_fail_exp.c` | exploit - AF_ALG splice loop |
| `payload.c` | injected binary - setuid shell dropper, no libc |
| `copy_fail_exp.py` | ungolfed Python reference implementation |

## References

- https://copy.fail/
- CVE-2026-31431
