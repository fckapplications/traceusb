# Portable SQLite slot

TraceUSB can use a bundled portable `sqlite3.exe` from this folder without
requiring SQLite to be installed on the reviewed computer.

Expected files:

```text
tools/sqlite/win-x64/sqlite3.exe
tools/sqlite/win-x64/sqlite3.exe.sha256
```

The `.sha256` file must contain the SHA256 hash of `sqlite3.exe`, either by
itself or in the common `HASH  filename` format.

If this folder is empty, TraceUSB can still use:

1. `-SQLiteCliPath` for an explicit operator-supplied SQLite CLI.
2. `-PortableSQLitePath` for a pinned portable executable.
3. `sqlite3.exe` available on `PATH`.
4. The pinned temporary download configured in `TraceUSB.ps1`.

The temporary download is extracted under `%TEMP%` and removed after the
browser-history scan finishes.
