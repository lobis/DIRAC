import os
import tempfile
import unittest
from unittest.mock import MagicMock

import pytest

pytest.importorskip("XRootD.client")
from XRootD.client import CopyProcess, FileSystem
from XRootD.client import flags as _Flags
from XRootD.client.responses import XRootDStatus

import DIRAC.Resources.Storage.XROOTStorage as xrootStorage
from DIRAC.Resources.Storage.CTAStorage import CTAStorage
from DIRAC.Resources.Storage.XROOTStorage import XROOTStorage

if not hasattr(FileSystem, "stat_info"):
    pytest.skip("Requires native helpers from lobis/xrootd PR #57", allow_module_level=True)

TEST_SOURCE_FILE = os.path.join(tempfile.gettempdir(), "source_test_file")


class _Status(XRootDStatus):
    def __init__(self, ok=True, message="", errCode=0, errNo=0, shellcode=0):
        super().__init__(
            {
                "ok": ok,
                "message": message,
                "code": 0 if ok else (errCode or self.errOSError),
                "errno": 0 if ok else errNo,
                "shellcode": shellcode,
            }
        )


class _StatInfo:
    def __init__(self, size=4, flags=0, modtime=0):
        self.size = size
        self.flags = flags
        self.modtime = modtime


class _DirEntry:
    def __init__(self, name, statinfo):
        self.name = name
        self.statinfo = statinfo


_StatInfoFlags = _Flags.StatInfoFlags


class _FileSystem(FileSystem):
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.mkdir_calls = []
        self.prepare_calls = []

    def stat(self, path, timeout=0):
        if "not_found" in path:
            return (
                _Status(
                    ok=False, message="No such file or directory", errCode=XRootDStatus.errErrorResponse, errNo=3011
                ),
                None,
            )
        if "error_file" in path:
            return (
                _Status(ok=False, message="Permission denied", errCode=XRootDStatus.errErrorResponse, errNo=3010),
                None,
            )
        return _Status(), _StatInfo()

    def query(self, queryCode, path, timeout=0):
        return _Status(), b"adler32 deadbeef\n\0"

    def mkdir(self, path, flags, mode=0, timeout=0):
        self.mkdir_calls.append((path, flags))
        return _Status(), None

    def dirlist(self, path, flags=0, timeout=0):
        return _Status(), [
            _DirEntry("file.dat", _StatInfo()),
            _DirEntry("subdir", _StatInfo(flags=_StatInfoFlags.IS_DIR)),
        ]

    def rm(self, path, timeout=0):
        return self.stat(path, timeout)[0], None

    def rmdir(self, path, timeout=0):
        return _Status(), None

    def prepare(self, paths, flags):
        self.prepare_calls.append((paths, flags))
        return _Status(), None


class _CopyProcess(CopyProcess):
    jobs = []

    def __init__(self):
        pass

    def add_job(self, *args, **kwargs):
        self.jobs.append((args, kwargs))

    def prepare(self):
        return _Status()

    def run(self, handler=None):
        return _Status(), []


class _StageResponse:
    request_id = "request-1"


class _StageStatus:
    def is_on_disk(self, path):
        return path == "root://host//path/voName/file"


class _ArchiveInfoItem:
    def __init__(self, url, locality="TAPE", error=None):
        self.url = url
        self.path = url
        self.locality = locality
        self.error = error


class _TapeClient:
    instances = []

    def __init__(self, timeout=-1):
        self.timeout = timeout
        self.calls = []
        self.instances.append(self)

    def archive_info(self, urls):
        self.calls.append(("archive_info", urls))
        return _Status(), [_ArchiveInfoItem(u, locality="DISK_AND_TAPE" if "both" in u else "TAPE") for u in urls]

    def stage(self, url, files, disk_lifetime=None):
        self.calls.append(("stage", url, files, disk_lifetime))
        return _Status(), _StageResponse()

    def stage_status(self, url, requestId):
        self.calls.append(("stage_status", url, requestId))
        return _Status(), _StageStatus()

    def release(self, url, requestId, paths):
        self.calls.append(("release", url, requestId, paths))
        return _Status()


class _Client:
    env = {}
    fs = None
    CopyProcess = _CopyProcess

    @classmethod
    def EnvPutString(cls, key, value):
        cls.env[key] = value
        return True

    @classmethod
    def EnvDelString(cls, key):
        cls.env.pop(key, None)
        return True

    @classmethod
    def FileSystem(cls, endpoint):
        cls.fs = _FileSystem(endpoint)
        return cls.fs


class XROOTStorageTestCase(unittest.TestCase):
    def setUp(self):
        self.oldClient = xrootStorage._xrootd_client
        self.oldFlags = xrootStorage._xrootd_flags
        self.oldTapeClient = xrootStorage._xrootd_tape_client
        self.oldProxyLocation = xrootStorage.getProxyLocation
        self.oldEnv = {
            "X509_USER_PROXY": os.environ.get("X509_USER_PROXY"),
            "XrdSecPROTOCOL": os.environ.get("XrdSecPROTOCOL"),
            "XrdSecGSIDELEGPROXY": os.environ.get("XrdSecGSIDELEGPROXY"),
        }
        self.addCleanup(self._restoreXRootGlobals)
        self.addCleanup(self._restoreEnv)
        xrootStorage._xrootd_client = _Client
        xrootStorage._xrootd_flags = _Flags
        xrootStorage._xrootd_tape_client = _TapeClient
        xrootStorage.getProxyLocation = lambda: None
        _CopyProcess.jobs = []
        _TapeClient.instances = []
        _Client.env = {}
        _Client.fs = None

        self.parameters = {
            "Protocol": "root",
            "Path": "/path",
            "Host": "host",
            "Port": "",
            "SvcClass": "spaceToken",
            "WSPath": "wspath",
            "ChecksumType": "adler32",
        }

    def _restoreXRootGlobals(self):
        xrootStorage._xrootd_client = self.oldClient
        xrootStorage._xrootd_flags = self.oldFlags
        xrootStorage._xrootd_tape_client = self.oldTapeClient
        xrootStorage.getProxyLocation = self.oldProxyLocation

    def _restoreEnv(self):
        for key, val in self.oldEnv.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    def _resource(self):
        resource = XROOTStorage("storageName", self.parameters)
        resource.se = MagicMock()
        resource.se.vo = "voName"
        return resource

    def test_construct_url_from_lfn_uses_double_slash_and_svc_class(self):
        resource = self._resource()

        res = resource.constructURLFromLFN("/voName/path/to/file")

        self.assertTrue(res["OK"])
        self.assertEqual("root://host//path/voName/path/to/file?svcClass=spaceToken", res["Value"])

    def test_file_metadata_uses_native_stat_and_checksum(self):
        resource = self._resource()

        res = resource.getFileMetadata("root://host//path/voName/file")

        self.assertTrue(res["OK"])
        metadata = res["Value"]["Successful"]["root://host//path/voName/file"]
        self.assertEqual(4, metadata["Size"])
        self.assertEqual("deadbeef", metadata["Checksum"])

    def test_exists_handles_success_not_found_and_errors(self):
        resource = self._resource()

        res = resource.exists(
            [
                "root://host//path/voName/file",
                "root://host//path/voName/not_found",
                "root://host//path/voName/error_file",
            ]
        )

        self.assertTrue(res["OK"])
        self.assertTrue(res["Value"]["Successful"]["root://host//path/voName/file"])
        self.assertFalse(res["Value"]["Successful"]["root://host//path/voName/not_found"])
        self.assertIn("root://host//path/voName/error_file", res["Value"]["Failed"])

    def test_storage_path_to_lfn_boundary(self):
        resource = self._resource()
        self.assertEqual("/voName/file", resource._storagePathToLFN("/path/voName/file"))
        self.assertEqual("/path2/voName/file", resource._storagePathToLFN("/path2/voName/file"))

    def test_put_file_uses_copy_process_with_parent_creation(self):
        resource = self._resource()

        res = resource.putFile({"root://host//path/voName/file": TEST_SOURCE_FILE}, sourceSize=4)

        self.assertTrue(res["OK"])
        self.assertFalse(res["Value"]["Failed"])
        args, kwargs = _CopyProcess.jobs[0]
        self.assertEqual(f"file://{os.path.abspath(TEST_SOURCE_FILE)}", args[0])
        self.assertEqual("root://host//path/voName/file", args[1])
        self.assertTrue(kwargs["force"])
        self.assertTrue(kwargs["mkdir"])
        self.assertEqual(resource.xrootdTimeout, kwargs["inittimeout"])

    def test_native_helpers_preserve_errors_and_timeouts(self):
        resource = self._resource()
        fs = resource._filesystem()
        fs.stat = MagicMock(return_value=(_Status(ok=False, message="generic failure", errCode=400, errNo=3000), None))
        path = "root://host//path/voName/file"
        for operation in (resource.exists, resource.removeFile):
            result = operation(path)["Value"]
            self.assertIn(path, result["Failed"])
            self.assertNotIn(path, result["Successful"])
        fs.stat.assert_called_with("//path/voName/file", resource.xrootdTimeout)
        fs.stat = MagicMock(return_value=(_Status(ok=False, errCode=400, errNo=3011), None))
        self.assertFalse(resource.exists(path)["Value"]["Successful"][path])
        self.assertTrue(resource.removeFile(path)["Value"]["Successful"][path])

    def test_checksum_selects_algorithm_and_preserves_cgi(self):
        resource = self._resource()
        fs = resource._filesystem()
        fs.query = MagicMock(return_value=(_Status(), b"adler32 deadbeef"))
        self.assertEqual(resource._checksum("root://host//file?svcClass=hot&cks.type=md5"), "deadbeef")
        self.assertEqual(fs.query.call_args.args[1], "//file?svcClass=hot&cks.type=adler32")
        self.assertEqual(fs.query.call_args.kwargs["timeout"], resource.xrootdTimeout)
        fs.query.return_value = _Status(), b"md5 wrong"
        with self.assertRaises(OSError):
            resource._checksum("//file")

    def test_copy_checksums_and_size_validation(self):
        resource = self._resource()
        resource._getSingleFileSize = MagicMock(return_value=3)
        resource._removeSingleFile = MagicMock()
        path = "root://host//file"
        result = resource.putFile({path: TEST_SOURCE_FILE}, sourceSize=4)["Value"]
        self.assertIn(path, result["Failed"])
        resource._removeSingleFile.assert_called_once_with(path)
        options = _CopyProcess.jobs[-1][1]
        self.assertEqual(options["checksummode"], "end2end")
        self.assertEqual(options["checksumtype"], "adler32")
        resource.checksumType = None
        resource._copy("source", "target", 4)
        self.assertEqual(_CopyProcess.jobs[-1][1]["checksummode"], "none")

    def test_listing_preserves_query_and_does_not_repeat_storage_prefix(self):
        resource = self._resource()
        path = "root://host//path/voName?svcClass=hot"
        result = resource._listSingleDirectory(path, internalCall=True)
        self.assertIn("root://host//path/voName/file.dat?svcClass=hot", result["Files"])
        self.assertIn("root://host//path/voName/subdir?svcClass=hot", result["SubDirs"])
        result = resource._listSingleDirectory(path)
        self.assertIn("/voName/file.dat", result["Files"])

    def test_create_directory_rejects_existing_file(self):
        resource = self._resource()
        path = "root://host//file"
        result = resource.createDirectory(path)["Value"]
        self.assertIn(path, result["Failed"])
        self.assertNotIn(path, result["Successful"])

    def test_prestage_file_uses_tape_client_stage(self):
        resource = self._resource()

        res = resource.prestageFile(["root://host//path/voName/file1", "root://host//path/voName/file2"])

        self.assertTrue(res["OK"])
        self.assertEqual("request-1", res["Value"]["Successful"]["root://host//path/voName/file1"])
        self.assertEqual("request-1", res["Value"]["Successful"]["root://host//path/voName/file2"])
        self.assertEqual(
            [
                (
                    "stage",
                    "root://host//path/voName/file1",
                    ["root://host//path/voName/file1", "root://host//path/voName/file2"],
                    86400,
                )
            ],
            _TapeClient.instances[0].calls,
        )

    def test_prestage_file_passes_lifetime_to_tape_client(self):
        resource = self._resource()

        res = resource.prestageFile("root://host//path/voName/file", lifetime=3600)

        self.assertTrue(res["OK"])
        self.assertEqual("request-1", res["Value"]["Successful"]["root://host//path/voName/file"])
        self.assertEqual(
            [("stage", "root://host//path/voName/file", ["root://host//path/voName/file"], 3600)],
            _TapeClient.instances[0].calls,
        )

    def test_prestage_status_uses_tape_client_stage_status(self):
        resource = self._resource()

        res = resource.prestageFileStatus({"root://host//path/voName/file": "request-1"})

        self.assertTrue(res["OK"])
        self.assertTrue(res["Value"]["Successful"]["root://host//path/voName/file"])
        self.assertEqual(
            [("stage_status", "root://host//path/voName/file", "request-1")],
            _TapeClient.instances[0].calls,
        )

    def test_release_file_uses_tape_client_release(self):
        resource = self._resource()

        res = resource.releaseFile({"root://host//path/voName/file": "request-1"})

        self.assertTrue(res["OK"])
        self.assertEqual("request-1", res["Value"]["Successful"]["root://host//path/voName/file"])
        self.assertEqual(
            [("release", "root://host//path/voName/file", "request-1", ["root://host//path/voName/file"])],
            _TapeClient.instances[0].calls,
        )

    def test_configure_auth_deletes_invalid_x509_proxy_from_xrootd_env(self):
        _Client.env["X509_USER_PROXY"] = "$MISSING_PROXY"
        os.environ["X509_USER_PROXY"] = "$MISSING_PROXY"
        resource = self._resource()

        resource._configureAuth()

        self.assertNotIn("X509_USER_PROXY", _Client.env)
        self.assertNotIn("X509_USER_PROXY", os.environ)

    def test_cta_storage_file_metadata_enriches_with_tape_locality(self):
        resource = CTAStorage("storageName", self.parameters)
        resource.se = MagicMock()
        resource.se.vo = "voName"

        res = resource.getFileMetadata(["root://host//path/voName/file", "root://host//path/voName/both_file"])

        self.assertTrue(res["OK"])
        metadata = res["Value"]["Successful"]["root://host//path/voName/file"]
        self.assertEqual(4, metadata["Size"])
        self.assertEqual("deadbeef", metadata["Checksum"])
        self.assertEqual(0, metadata["Cached"])
        self.assertEqual(1, metadata["Migrated"])
        self.assertFalse(metadata["Accessible"])
        self.assertEqual("NEARLINE", metadata["user.status"])

        both_metadata = res["Value"]["Successful"]["root://host//path/voName/both_file"]
        self.assertEqual(1, both_metadata["Cached"])
        self.assertEqual(1, both_metadata["Migrated"])
        self.assertTrue(both_metadata["Accessible"])
        self.assertEqual("ONLINE_AND_NEARLINE", both_metadata["user.status"])

        self.assertEqual(
            [("archive_info", ["root://host//path/voName/file", "root://host//path/voName/both_file"])],
            _TapeClient.instances[0].calls,
        )


@pytest.fixture
def resource():
    case = XROOTStorageTestCase()
    case.setUp()
    try:
        yield case._resource()
    finally:
        case.doCleanups()


@pytest.mark.parametrize(
    "method",
    [
        "exists",
        "isFile",
        "isDirectory",
        "getFileSize",
        "getFileMetadata",
        "putFile",
        "getFile",
        "removeFile",
        "removeDirectory",
        "createDirectory",
        "listDirectory",
        "prestageFile",
        "prestageFileStatus",
        "releaseFile",
    ],
)
def test_invalid_bulk_arguments_return_dirac_error(resource, method):
    assert not getattr(resource, method)(123)["OK"]


@pytest.mark.parametrize("method,expected", [("isFile", True), ("isDirectory", False), ("getFileSize", 4)])
def test_metadata_queries_preserve_partial_success(resource, method, expected):
    result = getattr(resource, method)(["//file", "//error_file"])["Value"]
    assert result["Successful"] == {"//file": expected}
    assert "//error_file" in result["Failed"]


@pytest.mark.parametrize("method", ["getFileSize", "getFileMetadata"])
def test_file_metadata_rejects_directory(resource, method):
    resource._filesystem().stat = MagicMock(return_value=(_Status(), _StatInfo(flags=_StatInfoFlags.IS_DIR)))
    assert "//directory" in getattr(resource, method)("//directory")["Value"]["Failed"]


@pytest.mark.parametrize("code,number,success", [(0, 0, True), (400, 3011, True), (400, 3010, False)])
def test_rmdir_only_ignores_missing_directory(resource, code, number, success):
    resource._filesystem().rmdir = MagicMock(return_value=(_Status(ok=not code, errCode=code, errNo=number), None))
    result = resource.removeDirectory("//dir")["Value"]
    assert ("//dir" in result["Successful"]) is success
    assert ("//dir" in result["Failed"]) is not success


def test_listing_error_returns_failed_path(resource):
    resource._filesystem().dirlist = MagicMock(side_effect=PermissionError("denied"))
    assert "//dir" in resource.listDirectory("//dir")["Value"]["Failed"]


@pytest.mark.parametrize("source", ["file:///tmp/source", "root://host//source", "xroot://host//source"])
def test_copy_source_urls_are_preserved(resource, source):
    assert resource._putSingleFile("root://host//target", source, sourceSize=4) == 4
    assert _CopyProcess.jobs[-1][0][0] == source


def test_unsupported_copy_protocol_is_rejected_before_submission(resource):
    with pytest.raises(ValueError):
        resource._putSingleFile("root://host//target", "https://host/source", sourceSize=4)
    assert not _CopyProcess.jobs


def test_bad_download_is_removed_and_reported(resource, tmp_path):
    local = tmp_path / "file"
    local.write_bytes(b"bad")
    result = resource.getFile("root://host//file", localPath=str(tmp_path))["Value"]
    assert "root://host//file" in result["Failed"]
    assert not local.exists()


@pytest.mark.parametrize("operation", ["prestageFile", "prestageFileStatus", "releaseFile"])
def test_tape_failures_are_reported_for_all_paths(resource, operation):
    resource._tapeClient = MagicMock(side_effect=OSError("tape unavailable"))
    result = getattr(resource, operation)({"//one": "request", "//two": "request"})["Value"]
    assert set(result["Failed"]) == {"//one", "//two"}
    assert not result["Successful"]


def test_empty_stage_does_not_create_tape_client(resource):
    resource._tapeClient = MagicMock(side_effect=AssertionError("unneeded client"))
    assert resource.prestageFile([])["Value"] == {"Successful": {}, "Failed": {}}


@pytest.mark.parametrize(
    "locality,cached,migrated,accessible",
    [
        ("TAPE", 0, 1, False),
        ("DISK_AND_TAPE", 1, 1, True),
        ("DISK", 1, 0, True),
        ("LOST", 0, 0, False),
        ("UNAVAILABLE", 0, 0, False),
    ],
)
def test_cta_locality_contract(resource, locality, cached, migrated, accessible):
    cta = CTAStorage("test", {"Protocol": "root", "Host": "host", "Path": "/path"})
    metadata = {}
    cta._updateMetadataDict(metadata, {"locality": locality})
    assert (metadata["Cached"], metadata["Migrated"], metadata["Accessible"]) == (cached, migrated, accessible)


def test_cta_archive_errors_preserve_existing_metadata(resource):
    cta = CTAStorage("test", {"Protocol": "root", "Host": "host", "Path": "/path"})
    cta._tapeClient = MagicMock(side_effect=OSError("offline"))
    assert cta._fetchTapeArchiveInfo(["//file"]) == {}
    metadata = {"Size": 4}
    cta._enrichMetadata(metadata, "//file", {})
    cta._enrichMetadata(metadata, "//file", {"//other": _ArchiveInfoItem("//other")})
    cta._enrichMetadata(metadata, "//file", {"//file": _ArchiveInfoItem("//file", error="unavailable")})
    assert metadata == {"Size": 4}


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(XROOTStorageTestCase)
    unittest.TextTestRunner(verbosity=2).run(suite)


def test_valid_proxy_is_configured_and_missing_proxy_is_cleared(resource, tmp_path, monkeypatch):
    proxy = tmp_path / "x509.proxy"
    proxy.write_text("test fixture")
    monkeypatch.setattr(xrootStorage, "getProxyLocation", lambda: str(proxy))
    resource._configureAuth()
    assert _Client.env["X509_USER_PROXY"] == str(proxy)
    assert os.environ["X509_USER_PROXY"] == str(proxy)
    proxy.unlink()
    resource._configureAuth()
    assert "X509_USER_PROXY" not in _Client.env
    assert "X509_USER_PROXY" not in os.environ


def test_missing_optional_bindings_have_actionable_errors(resource, monkeypatch):
    monkeypatch.setattr(xrootStorage, "_xrootd_client", None)
    monkeypatch.setattr(xrootStorage, "_xrootd_flags", None)
    monkeypatch.setattr(xrootStorage, "_xrootd_tape_client", None)
    for method in (resource._client, resource._flags, resource._tapeClient):
        with pytest.raises(RuntimeError, match="Missing dependency"):
            method()


def test_failed_tape_status_is_not_success(resource):
    tape = MagicMock()
    tape.stage.return_value = _Status(ok=False, message="stage failed"), None
    resource._tapeClient = lambda: tape
    assert "//file" in resource.prestageFile("//file")["Value"]["Failed"]


def test_disabled_checksum_does_not_query_server(resource):
    resource.checksumType = None
    resource._filesystem().query = MagicMock(side_effect=AssertionError("unexpected query"))
    assert resource._checksum("//file") is None
    assert "//file" in resource.getFileMetadata("//file")["Value"]["Successful"]


def test_url_helper_handles_absolute_urls_and_invalid_base(resource):
    url = "root://other//file?token=opaque"
    assert resource._pathToURL(url) == url
    resource.getURLBase = lambda: {"OK": True, "Value": "root://host//path?svcClass=spaceToken"}
    assert resource._pathToURL("//file").endswith("//file?svcClass=spaceToken")
    resource.getURLBase = lambda: {"OK": False, "Message": "bad base"}
    with pytest.raises(ValueError, match="bad base"):
        resource._pathToURL("//file")
