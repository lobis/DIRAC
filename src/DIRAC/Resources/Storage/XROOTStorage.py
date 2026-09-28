"""Native XRootD storage plugin."""

import datetime
import os
from urllib import parse

from DIRAC import S_OK, gLogger
from DIRAC.Core.Security.Locations import getProxyLocation
from DIRAC.Core.Utilities.File import getSize
from DIRAC.Core.Utilities.Pfn import pfnparse, pfnunparse
from DIRAC.Resources.Storage.StorageBase import StorageBase
from DIRAC.Resources.Storage.Utilities import checkArgumentFormat

try:
    from XRootD import client as _xrootd_client
    from XRootD.client import flags as _xrootd_flags
except ImportError:
    _xrootd_client = None
    _xrootd_flags = None

try:
    from XRootD.client.tape import TapeClient as _xrootd_tape_client
except ImportError:
    _xrootd_tape_client = None


MAX_SINGLE_STREAM_SIZE = 1024 * 1024 * 10
MIN_BANDWIDTH = 0.5 * (1024 * 1024)


class XROOTStorage(StorageBase):
    """XRootD interface to StorageElement using the native Python bindings."""

    _INPUT_PROTOCOLS = ["file", "root", "xroot"]
    _OUTPUT_PROTOCOLS = ["root"]

    PROTOCOL_PARAMETERS = StorageBase.PROTOCOL_PARAMETERS + ["SvcClass"]
    DYNAMIC_OPTIONS = {"SvcClass": "svcClass"}

    def __init__(self, storageName, parameters):
        super().__init__(storageName, parameters)
        self.srmSpecificParse = False
        self.log = gLogger.getSubLogger(self.__class__.__name__).getSubLogger(storageName)
        self.pluginName = "XROOT"
        self.protocolParameters["WSUrl"] = 0
        self.protocolParameters["SpaceToken"] = 0
        self._defaultExtendedAttributes = None
        self.__fs = None

        self.stageTimeout = int(parameters.get("StageTimeout", 12 * 60 * 60) or 12 * 60 * 60)
        self.xrootdTimeout = int(parameters.get("XRootDTimeout", parameters.get("GFAL_Timeout", 100)) or 100)
        self.checksumType = parameters.get("ChecksumType", "0")
        if self.checksumType == "0":
            self.checksumType = None

    @staticmethod
    def _client():
        if _xrootd_client is None:
            raise RuntimeError("Missing dependency: native Python helpers from lobis/xrootd PR #57")
        return _xrootd_client

    @staticmethod
    def _flags():
        if _xrootd_flags is None:
            raise RuntimeError("Missing dependency: native Python helpers from lobis/xrootd PR #57")
        return _xrootd_flags

    @staticmethod
    def _statusOK(status):
        return bool(getattr(status, "ok", False))

    @staticmethod
    def _statusMessage(status):
        return str(getattr(status, "message", status))

    @classmethod
    def _ensureOK(cls, status):
        if status is not None and cls._statusOK(status):
            return
        raise RuntimeError(cls._statusMessage(status))

    def _estimateTransferTimeout(self, fileSize):
        return int(fileSize / MIN_BANDWIDTH * 4 + 310)

    def _configureAuth(self):
        if "XrdSecPROTOCOL" not in os.environ:
            os.environ["XrdSecPROTOCOL"] = "gsi,unix"
        if "XrdSecGSIDELEGPROXY" not in os.environ:
            os.environ["XrdSecGSIDELEGPROXY"] = "1"

        self._setXRootDEnv("XrdSecPROTOCOL", os.environ["XrdSecPROTOCOL"])
        self._setXRootDEnv("XrdSecGSIDELEGPROXY", os.environ["XrdSecGSIDELEGPROXY"])

        proxyLocation = self._proxyLocation()
        if proxyLocation:
            os.environ["X509_USER_PROXY"] = proxyLocation
            self._setXRootDEnv("X509_USER_PROXY", proxyLocation)
        else:
            self._delXRootDEnv("X509_USER_PROXY")

    def _setXRootDEnv(self, key, value):
        self._client().EnvPutString(key, value)

    def _delXRootDEnv(self, key):
        os.environ.pop(key, None)
        self._client().EnvDelString(key)

    @staticmethod
    def _proxyLocation():
        proxyLocation = getProxyLocation()
        if not proxyLocation:
            proxyLocation = os.environ.get("X509_USER_PROXY")
        if not proxyLocation:
            return None
        proxyLocation = os.path.expanduser(os.path.expandvars(proxyLocation))
        if "$" in proxyLocation or not os.path.exists(proxyLocation):
            return None
        return proxyLocation

    def _endpoint(self):
        host = self.protocolParameters.get("Host", "")
        port = self.protocolParameters.get("Port")
        if port:
            return f"root://{host}:{port}"
        return f"root://{host}"

    def _filesystem(self):
        if self.__fs is None:
            self._configureAuth()
            self.__fs = self._client().FileSystem(self._endpoint())
        return self.__fs

    def _urlToPath(self, url):
        parsed = parse.urlparse(url)
        if parsed.scheme:
            path = parsed.path
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return path
        return url

    def _pathToURL(self, path):
        if parse.urlparse(path).scheme:
            return path
        result = self.getURLBase()
        if not result["OK"]:
            raise ValueError(result["Message"])
        base = parse.urlsplit(result["Value"])
        remotePath, separator, query = path.partition("?")
        return parse.urlunsplit(
            (base.scheme, base.netloc, "//" + remotePath.lstrip("/"), query if separator else base.query, "")
        )

    def _addDoubleSlash(self, res):
        if not res["OK"]:
            return res
        url = res["Value"]
        res = pfnparse(url, srmSpecific=self.srmSpecificParse)
        if not res["OK"]:
            return res
        urlDict = res["Value"]
        urlDict["Path"] = "/" + urlDict["Path"]

        try:
            proxyLoc = getProxyLocation()
            if proxyLoc:
                proxyLoc = os.path.basename(proxyLoc).replace(".", "")
                urlDict["Host"] = f"{proxyLoc}@{urlDict['Host']}"
        except Exception as e:
            self.log.warn(f"Exception trying to add virtual user in the url: {e!r}")

        return pfnunparse(urlDict, srmSpecific=self.srmSpecificParse)

    def getURLBase(self, withWSUrl=False):
        return self._addDoubleSlash(super().getURLBase(withWSUrl=withWSUrl))

    def constructURLFromLFN(self, lfn, withWSUrl=False):
        return self._addDoubleSlash(super().constructURLFromLFN(lfn=lfn, withWSUrl=withWSUrl))

    def getCurrentURL(self, fileName):
        return self._addDoubleSlash(super().getCurrentURL(fileName))

    def _stat(self, path):
        return self._filesystem().stat_info(self._urlToPath(path), timeout=self.xrootdTimeout)

    def _metadataFromStat(self, statInfo):
        flags = getattr(statInfo, "flags", 0)
        isDir = bool(flags & getattr(self._flags().StatInfoFlags, "IS_DIR", 1))
        modTime = getattr(statInfo, "modtime", 0)
        metadata = {
            "Size": int(getattr(statInfo, "size", 0)),
            "Directory": isDir,
            "File": not bool(flags & (self._flags().StatInfoFlags.IS_DIR | self._flags().StatInfoFlags.OTHER)),
            "FileFlags": flags,
            "ModTime": datetime.datetime.fromtimestamp(modTime) if modTime else None,
            "ChangeTime": None,
            "AccessTime": None,
        }
        if not isDir:
            metadata.update(
                {
                    "Mode": 0o644,
                    "Executable": False,
                    "Readable": True,
                    "Writeable": True,
                }
            )
        else:
            metadata["Mode"] = 0o755
        return self._addCommonMetadata(metadata)

    def _checksum(self, path):
        if not self.checksumType:
            return None
        _, digest = self._filesystem().checksum(
            self._urlToPath(path), algorithm=self.checksumType, timeout=self.xrootdTimeout
        )
        return digest

    def exists(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            try:
                successful[url] = self._filesystem().exists(self._urlToPath(url), timeout=self.xrootdTimeout)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def isDirectory(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            try:
                successful[url] = bool(self._metadataFromStat(self._stat(url))["Directory"])
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def isFile(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            try:
                successful[url] = bool(self._metadataFromStat(self._stat(url))["File"])
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def getFileSize(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            try:
                successful[url] = self._getSingleFileSize(url)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _getSingleFileSize(self, path):
        statInfo = self._stat(path)
        metadata = self._metadataFromStat(statInfo)
        if not metadata["File"]:
            raise IsADirectoryError("supplied path is not a file")
        return metadata["Size"]

    def putFile(self, path, sourceSize=0):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        urlDict = res["Value"]
        successful = {}
        failed = {}
        for destURL, srcFile in urlDict.items():
            try:
                size = self._putSingleFile(destURL, srcFile, sourceSize=sourceSize)
                successful[destURL] = size
            except Exception as e:
                failed[destURL] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _putSingleFile(self, destURL, srcFile, sourceSize=0):
        srcProtocol = parse.urlparse(srcFile).scheme
        if not srcProtocol:
            srcURL = f"file://{os.path.abspath(srcFile)}"
            if not sourceSize:
                sourceSize = getSize(srcFile)
        elif srcProtocol in ["file", "root", "xroot"]:
            srcURL = srcFile
        else:
            raise ValueError(f"{srcProtocol} is not a suitable input protocol")
        self._copy(srcURL, destURL, sourceSize)
        destSize = self._getSingleFileSize(destURL)
        if destSize == sourceSize:
            return destSize
        self._removeSingleFile(destURL)
        raise RuntimeError(f"Source and destination file size don't match ({sourceSize} vs {destSize})")

    def getFile(self, path, localPath=False):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for srcURL in res["Value"]:
            fileName = os.path.basename(self._urlToPath(srcURL).partition("?")[0].rstrip("/"))
            destFile = os.path.join(localPath if localPath else os.getcwd(), fileName)
            try:
                successful[srcURL] = self._getSingleFile(srcURL, destFile)
            except Exception as e:
                failed[srcURL] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _getSingleFile(self, srcURL, destFile):
        sourceSize = self._getSingleFileSize(srcURL)
        self._copy(srcURL, os.path.abspath(destFile), sourceSize)
        localSize = getSize(destFile)
        if localSize == sourceSize:
            return localSize
        try:
            os.remove(destFile)
        except Exception:
            self.log.debug(f"Failed to remove file {destFile}")
        raise RuntimeError(f"Remote and local filesizes don't match: {sourceSize} vs {localSize}")

    def _copy(self, source, target, fileSize):
        self._configureAuth()
        fileSize = int(fileSize or 0)
        timeout = self._estimateTransferTimeout(fileSize)
        self._client().CopyProcess.copy_one(
            source,
            target,
            force=True,
            mkdir=True,
            checksummode="end2end" if self.checksumType else "none",
            checksumtype=self.checksumType or "",
            cptimeout=timeout,
            inittimeout=self.xrootdTimeout,
            parallelchunks=4 if fileSize > MAX_SINGLE_STREAM_SIZE else 1,
        )

    def removeFile(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                successful[url] = self._removeSingleFile(url)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _removeSingleFile(self, path):
        self._filesystem().unlink(self._urlToPath(path), missing_ok=True, timeout=self.xrootdTimeout)
        return True

    def removeDirectory(self, path, recursive=False):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                successful[url] = self._removeSingleDirectory(url, recursive=recursive)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _removeSingleDirectory(self, path, recursive=False):
        if recursive:
            result = self._filesystem().remove_tree(self._urlToPath(path), missing_ok=True, timeout=self.xrootdTimeout)
            return {"FilesRemoved": result.files_removed, "SizeRemoved": result.size_removed}
        # rmdir keeps its native status-tuple API. Use the shared mapping so
        # only a missing directory is accepted, never permission/I/O errors.
        from XRootD.client.responses import raise_as_oserror

        status, _ = self._filesystem().rmdir(self._urlToPath(path), timeout=self.xrootdTimeout)
        try:
            raise_as_oserror(status, path)
        except FileNotFoundError:
            pass
        return {"FilesRemoved": 0, "SizeRemoved": 0}

    def getFileMetadata(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        urls = res["Value"]

        tapeInfo = self._fetchTapeArchiveInfo(urls)

        for url in urls:
            try:
                metadata = self._metadataFromStat(self._stat(url))
                if not metadata["File"]:
                    raise IsADirectoryError("supplied path is not a file")
                checksum = self._checksum(url)
                if checksum:
                    metadata["Checksum"] = checksum
                self._enrichMetadata(metadata, url, tapeInfo)
                successful[url] = metadata
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _fetchTapeArchiveInfo(self, urls):
        """Hook to fetch tape archive info for a batch of URLs. Overridden in TapeStorage."""
        return {}

    def _enrichMetadata(self, metadata, url, tapeInfo=None):
        """Hook for subclasses to enrich file metadata. Overridden in TapeStorage."""
        pass

    def createDirectory(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                self._filesystem().makedirs(self._urlToPath(url), exist_ok=True, timeout=self.xrootdTimeout)
                successful[url] = True
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def listDirectory(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                successful[url] = self._listSingleDirectory(url)
            except Exception as e:
                failed[url] = f"Failed to list directory: {repr(e)}"
        return S_OK({"Failed": failed, "Successful": successful})

    def _listSingleDirectory(self, path, internalCall=False):
        xrootdPath = self._urlToPath(path)
        listing = self._filesystem().scandir(xrootdPath, timeout=self.xrootdTimeout)
        files = {}
        subDirs = {}
        for entry in listing:
            entryPath = entry.path
            entryURL = self._pathToURL(entryPath)
            statInfo = entry.stat()
            metadata = self._metadataFromStat(statInfo)
            outputPath = entryURL if internalCall else self._storagePathToLFN(entryPath)
            if metadata["Directory"]:
                subDirs[outputPath] = metadata
            elif metadata["File"]:
                files[outputPath] = metadata
        return {"SubDirs": subDirs, "Files": files}

    def _storagePathToLFN(self, path):
        basePath = os.path.normpath(self.protocolParameters["Path"])
        normPath = os.path.normpath("/" + path.partition("?")[0].lstrip("/"))
        if basePath and (normPath == basePath or normPath.startswith(basePath.rstrip("/") + "/")):
            lfn = normPath[len(basePath) :]
            return lfn if lfn.startswith("/") else f"/{lfn}"
        return normPath

    def _tapeClient(self):
        if _xrootd_tape_client is None:
            raise RuntimeError("Missing dependency: xrootd>=6.2.0 with TapeClient support")
        self._configureAuth()
        return _xrootd_tape_client(timeout=self.stageTimeout)

    def prestageFile(self, path, lifetime=86400):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        urls = list(res["Value"])
        if not urls:
            return S_OK({"Failed": failed, "Successful": successful})
        try:
            client = self._tapeClient()
            status, response = client.stage(urls[0], urls, disk_lifetime=lifetime)
            self._ensureOK(status)
            reqId = getattr(response, "request_id", getattr(response, "requestId", getattr(response, "id", None)))
            for url in urls:
                successful[url] = reqId
        except Exception as e:
            for url in urls:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def prestageFileStatus(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        client = None
        for url, token in res["Value"].items():
            try:
                if client is None:
                    client = self._tapeClient()
                status, response = client.stage_status(url, str(token))
                self._ensureOK(status)
                successful[url] = response.is_on_disk(url)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def releaseFile(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        client = None
        for url, token in res["Value"].items():
            try:
                if client is None:
                    client = self._tapeClient()
                tokenStr = str(token)
                status = client.release(url, tokenStr, [url])
                self._ensureOK(status)
                successful[url] = tokenStr
            except Exception as e:
                failed[url] = f"Error occurred while releasing file {e!r}"
        return S_OK({"Failed": failed, "Successful": successful})
