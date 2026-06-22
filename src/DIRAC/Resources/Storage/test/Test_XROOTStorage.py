import unittest
from unittest.mock import MagicMock

import DIRAC.Resources.Storage.XROOTStorage as xrootStorage
from DIRAC.Resources.Storage.XROOTStorage import XROOTStorage


class _Status:
    def __init__(self, ok=True, message=""):
        self.ok = ok
        self.message = message
        self.errNotFound = 304
        self.code = 0 if ok else 304
        self.shellcode = 0 if ok else 54


class _StatInfo:
    def __init__(self, size=4, flags=0, modtime=0):
        self.size = size
        self.flags = flags
        self.modtime = modtime


class _DirEntry:
    def __init__(self, name, statinfo):
        self.name = name
        self.statinfo = statinfo


class _QueryCode:
    CHECKSUM = 1


class _MkDirFlags:
    MAKEPATH = 1


class _DirListFlags:
    STAT = 1


class _StatInfoFlags:
    IS_DIR = 1
    OTHER = 2


class _PrepareFlags:
    STAGE = 1


class _Flags:
    QueryCode = _QueryCode
    MkDirFlags = _MkDirFlags
    DirListFlags = _DirListFlags
    StatInfoFlags = _StatInfoFlags
    PrepareFlags = _PrepareFlags


class _FileSystem:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.mkdir_calls = []
        self.prepare_calls = []

    def stat(self, path):
        return _Status(), _StatInfo()

    def query(self, queryCode, path):
        return _Status(), b"adler32 deadbeef\n\0"

    def mkdir(self, path, flags):
        self.mkdir_calls.append((path, flags))
        return _Status(), None

    def dirlist(self, path, flags):
        return _Status(), [
            _DirEntry("file.dat", _StatInfo()),
            _DirEntry("subdir", _StatInfo(flags=_StatInfoFlags.IS_DIR)),
        ]

    def rm(self, path):
        return _Status(), None

    def rmdir(self, path):
        return _Status(), None

    def prepare(self, paths, flags):
        self.prepare_calls.append((paths, flags))
        return _Status(), None


class _CopyProcess:
    jobs = []

    def add_job(self, *args, **kwargs):
        self.jobs.append((args, kwargs))

    def prepare(self):
        return _Status()

    def run(self):
        return _Status(), []


class _ArchiveInfo:
    locality = "ONLINE"


class _TapeRestClient:
    def __init__(self, timeout=-1, cert="", key="", verbosity=0):
        self.timeout = timeout
        self.cert = cert
        self.key = key
        self.verbosity = verbosity

    def archive_info(self, urls):
        return _Status(), [_ArchiveInfo()]


class _Client:
    env = {}
    fs = None
    CopyProcess = _CopyProcess
    TapeRestClient = _TapeRestClient

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
        self.oldProxyLocation = xrootStorage.getProxyLocation
        self.oldX509UserProxy = xrootStorage.os.environ.get("X509_USER_PROXY")
        self.addCleanup(self._restoreXRootGlobals)
        self.addCleanup(self._restoreProxyEnv)
        xrootStorage._xrootd_client = _Client
        xrootStorage._xrootd_flags = _Flags
        xrootStorage.getProxyLocation = lambda: None
        _CopyProcess.jobs = []
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
        xrootStorage.getProxyLocation = self.oldProxyLocation

    def _restoreProxyEnv(self):
        if self.oldX509UserProxy is None:
            xrootStorage.os.environ.pop("X509_USER_PROXY", None)
        else:
            xrootStorage.os.environ["X509_USER_PROXY"] = self.oldX509UserProxy

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

    def test_put_file_uses_copy_process_with_parent_creation(self):
        resource = self._resource()

        res = resource.putFile({"root://host//path/voName/file": "/tmp/source"}, sourceSize=4)

        self.assertTrue(res["OK"])
        self.assertFalse(res["Value"]["Failed"])
        args, kwargs = _CopyProcess.jobs[0]
        self.assertEqual("/tmp/source", args[0])
        self.assertEqual("root://host//path/voName/file", args[1])
        self.assertTrue(kwargs["force"])
        self.assertTrue(kwargs["mkdir"])

    def test_prestage_status_uses_tape_rest_archive_info(self):
        resource = self._resource()

        res = resource.prestageFileStatus({"root://host//path/voName/file": "token"})

        self.assertTrue(res["OK"])
        self.assertTrue(res["Value"]["Successful"]["root://host//path/voName/file"])

    def test_configure_auth_deletes_invalid_x509_proxy_from_xrootd_env(self):
        _Client.env["X509_USER_PROXY"] = "$MISSING_PROXY"
        xrootStorage.os.environ["X509_USER_PROXY"] = "$MISSING_PROXY"
        resource = self._resource()

        resource._configureAuth()

        self.assertNotIn("X509_USER_PROXY", _Client.env)
        self.assertNotIn("X509_USER_PROXY", xrootStorage.os.environ)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(XROOTStorageTestCase)
    unittest.TextTestRunner(verbosity=2).run(suite)
