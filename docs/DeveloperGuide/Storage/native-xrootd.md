# Native XRootD integration experiment

This change belongs to `lobis/DIRAC#2`, based on the fork's `integration`
branch. It requires the Python helpers from `lobis/xrootd#57`; it does not
claim compatibility with an unmodified XRootD 6.2 release. The native-storage
workflow pins an immutable implementation commit. Benchmark material is
excluded from the source branch. No fsspec dependency or global protocol
registration is needed here.

The classic XRootD bindings and synchronous helpers remain installable on
Python 3.6 (AlmaLinux 8). The optional native asyncio and fsspec interfaces
require Python 3.11 or later and raise a clear `ImportError` on older Python.
DIRAC already requires Python >= 3.11, so both interfaces are available to this
integration. All distributed XRootD Python files retain Python 3.6-compatible
syntax for installation and byte-compilation on AlmaLinux 8.

## Interfaces adopted

| DIRAC operation | Native interface | Benefit |
| --- | --- | --- |
| Metadata | `FileSystem.stat_info` | Native StatInfo with standard OSError failures |
| Existence | `FileSystem.exists` | False only for missing paths; other errors propagate |
| Checksums | `FileSystem.checksum(algorithm=...)` | Select and validate the algorithm; preserve CGI parameters |
| Listings | `FileSystem.scandir` | Remote paths, metadata fallback, and query preservation |
| Create directories | `FileSystem.makedirs(exist_ok=True)` | Existing files are rejected |
| Remove files | `FileSystem.unlink(missing_ok=True)` | Idempotence without hiding permission or I/O errors |
| Remove trees | `FileSystem.remove_tree` | Shared traversal, root protection, and removal counts |
| Transfers | `CopyProcess.copy_one` | Preparation, global and per-job failures are checked |

Transfers pass `checksummode="end2end"` and `checksumtype` when configured,
and retain destination-size validation. Unsupported checksums fail explicitly.
DIRAC's synchronous `S_OK` / `Successful` / `Failed` contract is preserved.
Listing LFNs and downloaded filenames exclude CGI, while remote operations
retain it. Native status objects in unit tests use the real response mapping.

Before (inside the plugin):

```python
status, reply = fs.query(flags.QueryCode.CHECKSUM, path)
# Check status, decode bytes, parse tokens, check the selected algorithm...
```

After:

```python
algorithm, digest = fs.checksum(path, algorithm="adler32", timeout=5)
info = fs.stat_info(path, timeout=5)
fs.unlink(path, missing_ok=True, timeout=5)
```

The stat_info helpers and synchronous unlink were added to the XRootD fork in
a separate commit as gaps exposed by this consumer. Existing stat status-tuple
and async stat native-exception contracts are unchanged.

## Async usage and boundary

DIRAC StorageBase methods are synchronous. Calling them from a coroutine still
blocks that coroutine; this PR does not rename a blocking method to async.
An async consumer can use the native interface directly:

```python
from XRootD.client import aio
import asyncio

async def inspect(url):
    async with aio.open(url, timeout=5) as file:
        header, next_block = await asyncio.gather(
            file.read_at(0, 64), file.read_at(64, 64)
        )
        # Positioned reads preserve the sequential cursor.
        async for chunk in file.iter_chunks(1024 * 1024):
            consume(chunk)
    return header, next_block
```

File I/O uses XrdCl callbacks and asyncio futures, not a Python executor.
Stream cancellation drains submitted requests before closing the native handle;
it does not promise transport-level cancellation. The integration test uploads
through DIRAC and reads the same bytes with concurrent `read_at` and
`iter_chunks`, rejecting any call to `run_in_executor`.

## Proposed follow-up commits (not implemented)

1. **[Python] Add native async copy completion.** Introduce a C++ asynchronous
   copy entry point or owned native worker with a completion callback, exposed
   as `aio.CopyProcess.copy_one`. Preserve checksum/TPC/progress options.
   Marshal progress onto the event loop; cancellation requests native stop and
   awaits completion before releasing buffers, callbacks or job state. Test
   cancellation during prepare/transfer, callback-thread affinity, duplicate
   completion, per-job failures and checksum mismatch. An executor wrapper
   around today's blocking `run()` would not establish this contract.
2. **[Python] Add awaitable Tape REST operations.** Expose the existing native
   callback-capable prepare/query operations through `aio.FileSystem.prepare`
   and `aio.TapeClient.stage`, `stage_status`, `archive_info`, and `release`.
   Define whether cancelling a submitted stage
   only cancels the local wait or also requests remote stage cancellation;
   never silently cancel the remote request. Test partial per-file errors,
   timeouts, cleanup and late completion. CTA's metadata enrichment currently
   makes synchronous Tape REST calls and must remain explicitly synchronous.
3. **[Python] Match recursive-removal helpers in aio.** Add `aio.FileSystem.remove_tree`
   with the synchronous result fields and root guard. Define partial-removal
   reporting and cancellation between operations before supporting async DIRAC
   directory removal. Validate CGI preservation and non-regular entries.
4. **[Resources] Introduce an explicit async storage contract.** After the copy
   and tape lifecycle contracts exist, add a separate async storage interface
   with bounded per-path concurrency and DIRAC result aggregation. Do not use
   `asyncio.run` inside existing sync methods: callers may already own a loop.

## Tests

`Test_XROOTStorage.py` covers the real native helper implementation with
controlled low-level responses, including server error codes, checksum
selection, partial failures and CTA locality mapping. `Test_XROOTStorageNative.py`
starts its own temporary local server when `XROOTD` and `XRDFS` are set. It never
accepts an external server address, so all mutations remain inside the fixture.
The fork CI builds the pinned XRootD server/bindings and runs both suites with
branch coverage. Tape REST tests use controlled responses; a real authenticated
CTA endpoint is still required for tape integration validation.
