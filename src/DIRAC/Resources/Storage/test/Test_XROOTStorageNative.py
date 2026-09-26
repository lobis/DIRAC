"""Exercise DIRAC with real native bindings and an isolated local server.

Set XROOTD and XRDFS to enable these tests. No external endpoint is used.
"""

import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytest.importorskip("XRootD.client")
from XRootD import client
from XRootD.client import aio

from DIRAC.Resources.Storage.XROOTStorage import XROOTStorage

if not hasattr(client.FileSystem, "stat_info"):
    pytest.skip("Requires native helpers from lobis/xrootd PR #57", allow_module_level=True)


@pytest.fixture(scope="module")
def localServer():
    executable = os.environ.get("XROOTD")
    xrdfs = os.environ.get("XRDFS")
    if not executable or not xrdfs:
        pytest.skip("Set XROOTD and XRDFS to run native storage integration tests")
    # Keep Unix admin socket paths short, including on macOS.
    directory = Path(tempfile.mkdtemp(prefix="dirac-xrd-", dir="/tmp"))
    server = None
    try:
        (directory / "data").mkdir()
        config = directory / "xrootd.cfg"
        config.write_text(
            f"all.export /\nall.adminpath {directory}\nall.pidpath {directory}\n"
            f"oss.localroot {directory}/data\nxrootd.chksum adler32 chkcgi\n"
        )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (directory / "server.log").open("wb") as log:
            server = subprocess.Popen(
                [executable, "-c", str(config), "-n", "dirac", "-p", str(port), "-I", "v4"],
                cwd=directory,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        endpoint = f"root://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        while True:
            if server.poll() is not None or time.monotonic() > deadline:
                pytest.fail((directory / "server.log").read_text())
            try:
                ready = subprocess.run([xrdfs, endpoint, "stat", "/"], capture_output=True, timeout=2)
                if ready.returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(0.05)
        yield endpoint, port
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        shutil.rmtree(directory)


@pytest.fixture
def storage(localServer, monkeypatch):
    import DIRAC.Resources.Storage.XROOTStorage as module

    keys = ("XrdSecPROTOCOL", "XrdSecGSIDELEGPROXY", "X509_USER_PROXY")
    nativeEnv = {key: client.EnvGetString(key) for key in keys}
    for key in keys:
        # Enroll every environment change made by _configureAuth for teardown.
        if key in os.environ:
            monkeypatch.setenv(key, os.environ[key])
        else:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("X509_USER_PROXY", raising=False)
    # Unix authentication to the local fixture only; preserve process env.
    monkeypatch.setenv("XrdSecPROTOCOL", "unix")
    monkeypatch.setattr(module, "getProxyLocation", lambda: None)
    resource = XROOTStorage(
        "native-test",
        {
            "Protocol": "root",
            "Host": "127.0.0.1",
            "Port": localServer[1],
            "Path": "/data",
            "ChecksumType": "adler32",
            "XRootDTimeout": 5,
        },
    )
    resource.se = MagicMock()
    resource.se.vo = "test"
    try:
        yield resource
    finally:
        for key, value in nativeEnv.items():
            if value is None:
                client.EnvDelString(key)
            else:
                client.EnvPutString(key, value)


def successful(result):
    assert result["OK"], result
    assert not result["Value"]["Failed"], result
    return result["Value"]["Successful"]


def test_native_copy_metadata_listing_and_removal(storage, localServer, tmp_path):
    root = localServer[0] + "//data/tree"
    url = root + "/child/file.bin"
    data = b"native DIRAC\x00\n" * 100
    source = tmp_path / "source"
    source.write_bytes(data)
    successful(storage.createDirectory(root + "/child"))
    assert successful(storage.putFile({url: str(source)}))[url] == len(data)
    metadata = successful(storage.getFileMetadata(url))[url]
    assert metadata["Size"] == len(data)
    assert metadata["Checksum"]
    listing = successful(storage.listDirectory(root + "/child?svcClass=hot"))
    assert "/tree/child/file.bin" in listing[root + "/child?svcClass=hot"]["Files"]
    destination = tmp_path / "download"
    destination.mkdir()
    successful(storage.getFile(url + "?svcClass=hot", localPath=str(destination)))
    assert (destination / "file.bin").read_bytes() == data
    counts = successful(storage.removeDirectory(root, recursive=True))[root]
    assert counts == {"FilesRemoved": 1, "SizeRemoved": len(data)}
    assert successful(storage.exists(url))[url] is False
    successful(storage.removeFile(url))
    successful(storage.removeDirectory(root, recursive=True))


def test_native_errors_remain_per_path(storage, localServer, tmp_path):
    url = localServer[0] + "//data/error-file"
    source = tmp_path / "source"
    source.write_bytes(b"data")
    successful(storage.putFile({url: str(source)}))
    result = storage.createDirectory(url)
    assert url in result["Value"]["Failed"]
    result = storage.getFileMetadata([url, url + "-missing"])
    assert url in result["Value"]["Successful"]
    assert url + "-missing" in result["Value"]["Failed"]
    successful(storage.removeFile(url))


def test_async_native_stream_reads_dirac_upload(storage, localServer, tmp_path, monkeypatch):
    url = localServer[0] + "//data/async-file"
    source = tmp_path / "source"
    source.write_bytes(b"abcdefgh")
    successful(storage.putFile({url: str(source)}))

    async def read():
        loop = asyncio.get_running_loop()

        def noExecutor(*args, **kwargs):
            raise AssertionError("Native async I/O must not use a Python executor")

        monkeypatch.setattr(loop, "run_in_executor", noExecutor)
        fs = aio.FileSystem(localServer[0])
        assert (await fs.stat_info("//data/async-file", timeout=5)).size == 8
        async with aio.open(url, timeout=5) as file:
            assert await asyncio.gather(file.read_at(4, 4), file.read_at(0, 4)) == [b"efgh", b"abcd"]
            assert file.tell() == 0
            assert b"".join([chunk async for chunk in file.iter_chunks(3)]) == b"abcdefgh"
        await fs.unlink("//data/async-file", timeout=5)

    try:
        asyncio.run(read())
    finally:
        successful(storage.removeFile(url))
