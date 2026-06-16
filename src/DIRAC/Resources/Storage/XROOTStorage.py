"""Native XRootD storage plugin."""

import datetime
import errno
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
except Exception:
    _xrootd_client = None
    _xrootd_flags = None


MAX_SINGLE_STREAM_SIZE = 1024 * 1024 * 10
MIN_BANDWIDTH = 0.5 * (1024 * 1024)


class MissingTapeRestMethod(RuntimeError):
    """Raised when the installed XRootD bindings do not expose a tape helper yet."""


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
            raise RuntimeError("Missing dependency: xrootd>=6.0.3")
        return _xrootd_client

    @staticmethod
    def _flags():
        if _xrootd_flags is None:
            raise RuntimeError("Missing dependency: xrootd>=6.0.3")
        return _xrootd_flags

    @staticmethod
    def _statusOK(status):
        return bool(getattr(status, "ok", False))

    @staticmethod
    def _statusMessage(status):
        return str(getattr(status, "message", status))

    @classmethod
    def _isNotFound(cls, status):
        if status is None:
            return False
        return (
            getattr(status, "code", None) == getattr(status, "errNotFound", None)
            or getattr(status, "shellcode", None) == 54
            or "No such file" in cls._statusMessage(status)
            or "not found" in cls._statusMessage(status).lower()
        )

    @classmethod
    def _isFileExists(cls, status):
        return status is not None and "file exists" in cls._statusMessage(status).lower()

    @classmethod
    def _ensureOK(cls, status):
        if status is not None and cls._statusOK(status):
            return
        raise RuntimeError(cls._statusMessage(status))

    @classmethod
    def _responseText(cls, response):
        if isinstance(response, bytes):
            return response.decode()
        return response

    def _estimateTransferTimeout(self, fileSize):
        return int(fileSize / MIN_BANDWIDTH * 4 + 310)

    def _configureAuth(self):
        client = self._client()

        if "XrdSecPROTOCOL" not in os.environ:
            os.environ["XrdSecPROTOCOL"] = "gsi,unix"
        if "XrdSecGSIDELEGPROXY" not in os.environ:
            os.environ["XrdSecGSIDELEGPROXY"] = "1"

        envPutString = getattr(client, "EnvPutString", None)
        if envPutString:
            envPutString("XrdSecPROTOCOL", os.environ["XrdSecPROTOCOL"])
            envPutString("XrdSecGSIDELEGPROXY", os.environ["XrdSecGSIDELEGPROXY"])

        proxyLocation = self._proxyLocation()
        if proxyLocation:
            os.environ["X509_USER_PROXY"] = proxyLocation
            if envPutString:
                envPutString("X509_USER_PROXY", proxyLocation)

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

    def _virtualUserHost(self):
        host = self.protocolParameters["Host"]
        try:
            proxyLocation = self._proxyLocation()
            if proxyLocation:
                proxyName = os.path.basename(proxyLocation).replace(".", "")
                return f"{proxyName}@{host}"
        except Exception as e:
            self.log.warn(f"Exception trying to add virtual user in the url: {repr(e)}")
        return host

    def _endpoint(self):
        port = self.protocolParameters.get("Port")
        host = self._virtualUserHost()
        if port:
            host = f"{host}:{port}"
        return f"{self.protocolParameters['Protocol']}://{host}"

    def _filesystem(self):
        if self.__fs is None:
            self._configureAuth()
            self.__fs = self._client().FileSystem(self._endpoint())
        return self.__fs

    def __addDoubleSlash(self, res):
        if not res["OK"]:
            return res
        url = res["Value"]
        res = pfnparse(url, srmSpecific=self.srmSpecificParse)
        if not res["OK"]:
            return res
        urlDict = res["Value"]
        urlDict["Path"] = "/" + urlDict["Path"].lstrip("/")
        urlDict["Host"] = self._virtualUserHost()
        res = pfnunparse(urlDict, srmSpecific=self.srmSpecificParse)
        if res["OK"]:
            res["Value"] = self._ensureDoubleSlashURL(res["Value"])
        return res

    @staticmethod
    def _ensureDoubleSlashURL(url):
        parsed = parse.urlsplit(url)
        if parsed.scheme in ("root", "xroot") and parsed.netloc and not parsed.path.startswith("//"):
            return parse.urlunsplit(
                (parsed.scheme, parsed.netloc, f"/{parsed.path}", parsed.query, parsed.fragment)
            )
        return url

    def getURLBase(self, withWSUrl=False):
        return self.__addDoubleSlash(super().getURLBase(withWSUrl=withWSUrl))

    def constructURLFromLFN(self, lfn, withWSUrl=False):
        return self.__addDoubleSlash(super().constructURLFromLFN(lfn=lfn, withWSUrl=withWSUrl))

    def getCurrentURL(self, fileName):
        return self.__addDoubleSlash(super().getCurrentURL(fileName))

    @staticmethod
    def _urlToPath(url):
        if "://" not in url:
            return url
        parsed = parse.urlparse(url)
        path = parsed.path or "/"
        if path.startswith("//"):
            return path[1:]
        return path

    def _pathToURL(self, path):
        return f"{self._endpoint()}/{path}"

    def _stat(self, path):
        status, statInfo = self._filesystem().stat(self._urlToPath(path))
        self._ensureOK(status)
        return statInfo

    def _isDirectoryStat(self, statInfo):
        statFlags = getattr(self._flags(), "StatInfoFlags", None)
        flags = getattr(statInfo, "flags", 0)
        if statFlags is not None:
            return bool(flags & statFlags.IS_DIR)
        return False

    def _isFileStat(self, statInfo):
        statFlags = getattr(self._flags(), "StatInfoFlags", None)
        flags = getattr(statInfo, "flags", 0)
        if statFlags is not None:
            return not bool(flags & statFlags.IS_DIR) and not bool(flags & getattr(statFlags, "OTHER", 0))
        return not self._isDirectoryStat(statInfo)

    @staticmethod
    def _convertTime(timestamp):
        if not timestamp:
            return "Never"
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

    def _metadataFromStat(self, statInfo):
        isFile = self._isFileStat(statInfo)
        isDirectory = self._isDirectoryStat(statInfo)
        metadata = {"File": isFile, "Directory": isDirectory}
        if isFile:
            metadata.update(
                {
                    "FileSerialNumber": getattr(statInfo, "id", 0),
                    "Mode": 0o644,
                    "Links": 1,
                    "UserID": 0,
                    "GroupID": 0,
                    "Size": int(getattr(statInfo, "size", 0)),
                    "LastAccess": "Never",
                    "ModTime": self._convertTime(getattr(statInfo, "modtime", 0)),
                    "StatusChange": self._convertTime(getattr(statInfo, "modtime", 0)),
                    "Executable": False,
                    "Readable": True,
                    "Writeable": True,
                }
            )
        elif isDirectory:
            metadata["Mode"] = 0o755
        return self._addCommonMetadata(metadata)

    def _checksum(self, path):
        if not self.checksumType:
            return None
        status, checksum = self._filesystem().query(self._flags().QueryCode.CHECKSUM, self._urlToPath(path))
        self._ensureOK(status)
        checksum = self._responseText(checksum).strip("\n\0")
        if not checksum:
            return None
        checksumType, checksumValue = checksum.split(None, 1)
        if checksumType.lower() == self.checksumType.lower():
            return checksumValue
        return None

    def exists(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            status, _ = self._filesystem().stat(self._urlToPath(url))
            if self._statusOK(status):
                successful[url] = True
            elif self._isNotFound(status):
                successful[url] = False
            else:
                failed[url] = self._statusMessage(status)
        return S_OK({"Failed": failed, "Successful": successful})

    def isFile(self, path):
        return self._statPredicate(path, self._isFileStat, "file")

    def isDirectory(self, path):
        return self._statPredicate(path, self._isDirectoryStat, "directory")

    def _statPredicate(self, path, predicate, kind):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        successful = {}
        failed = {}
        for url in res["Value"]:
            try:
                successful[url] = predicate(self._stat(url))
            except Exception as e:
                failed[url] = f"Failed to determine if path is a {kind}: {repr(e)}"
        return S_OK({"Failed": failed, "Successful": successful})

    def putFile(self, path, sourceSize=0):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for destURL, srcFile in res["Value"].items():
            if not srcFile:
                failed[destURL] = "Source file not set"
                continue
            try:
                successful[destURL] = self._putSingleFile(srcFile, destURL, sourceSize)
            except Exception as e:
                failed[destURL] = f"Failed to copy {srcFile} to {destURL}: {repr(e)}"
        return S_OK({"Failed": failed, "Successful": successful})

    def _putSingleFile(self, srcFile, destURL, sourceSize):
        srcProtocol = parse.urlparse(srcFile).scheme
        if not srcProtocol:
            srcURL = os.path.abspath(srcFile)
            if not sourceSize:
                sourceSize = getSize(srcFile)
        elif srcProtocol not in self.protocolParameters["InputProtocols"]:
            raise ValueError(f"{srcProtocol} is not a suitable input protocol")
        else:
            srcURL = srcFile
            if not sourceSize:
                raise ValueError("sourceSize argument is mandatory for TPC copy")
        self._copy(srcURL, destURL, sourceSize)
        if self.checksumType:
            return sourceSize
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
            fileName = os.path.basename(self._urlToPath(srcURL).rstrip("/"))
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
        timeout = self._estimateTransferTimeout(fileSize or 0)
        process = self._client().CopyProcess()
        process.add_job(
            source,
            target,
            force=True,
            mkdir=True,
            cptimeout=timeout,
            inittimeout=timeout or self.xrootdTimeout,
            parallelchunks=4 if fileSize > MAX_SINGLE_STREAM_SIZE else 1,
        )
        self._ensureOK(process.prepare())
        status, results = process.run()
        if not self._statusOK(status) and results:
            status = results[0].get("status", status)
        self._ensureOK(status)

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
        status, _ = self._filesystem().rm(self._urlToPath(path))
        if self._statusOK(status) or self._isNotFound(status):
            return True
        self._ensureOK(status)
        return True

    def getFileSize(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                successful[url] = self._getSingleFileSize(url)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _getSingleFileSize(self, path):
        statInfo = self._stat(path)
        if not self._isFileStat(statInfo):
            raise TypeError("Path is not a file")
        return int(getattr(statInfo, "size", 0))

    def getFileMetadata(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                metadata = self._metadataFromStat(self._stat(url))
                if not metadata["File"]:
                    raise TypeError(errno.EISDIR, "supplied path is not a file")
                checksum = self._checksum(url)
                if checksum:
                    metadata["Checksum"] = checksum
                successful[url] = metadata
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def createDirectory(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            status, _ = self._filesystem().mkdir(self._urlToPath(url), self._flags().MkDirFlags.MAKEPATH)
            if self._statusOK(status) or self._isFileExists(status):
                successful[url] = True
            else:
                failed[url] = self._statusMessage(status)
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
        status, listing = self._filesystem().dirlist(xrootdPath, self._flags().DirListFlags.STAT)
        self._ensureOK(status)
        files = {}
        subDirs = {}
        for entry in listing:
            entryName = getattr(entry, "name", str(entry))
            entryPath = os.path.join(xrootdPath.rstrip("/"), entryName)
            entryURL = self._pathToURL(entryPath)
            statInfo = getattr(entry, "statinfo", None)
            if statInfo is None:
                statInfo = self._stat(entryURL)
            metadata = self._metadataFromStat(statInfo)
            outputPath = entryURL if internalCall else self._storagePathToLFN(entryPath)
            if metadata["Directory"]:
                subDirs[outputPath] = metadata
            elif metadata["File"]:
                files[outputPath] = metadata
        return {"SubDirs": subDirs, "Files": files}

    def _storagePathToLFN(self, path):
        basePath = os.path.normpath(self.protocolParameters["Path"])
        normPath = os.path.normpath(path)
        if basePath and normPath.startswith(basePath):
            lfn = normPath[len(basePath) :]
            return lfn if lfn.startswith("/") else f"/{lfn}"
        return normPath

    def getDirectory(self, path, localPath=None):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for srcDir in res["Value"]:
            dirName = os.path.basename(self._urlToPath(srcDir).rstrip("/"))
            destDir = os.path.join(localPath if localPath else os.getcwd(), dirName)
            try:
                copyResult = self._getSingleDirectory(srcDir, destDir)
                if copyResult["AllGot"]:
                    successful[srcDir] = {"Files": copyResult["Files"], "Size": copyResult["Size"]}
                else:
                    failed[srcDir] = {"Files": copyResult["Files"], "Size": copyResult["Size"]}
            except Exception:
                failed[srcDir] = {"Files": 0, "Size": 0}
        return S_OK({"Failed": failed, "Successful": successful})

    def _getSingleDirectory(self, srcDir, destDir):
        os.makedirs(destDir, exist_ok=True)
        directoryListing = self._listSingleDirectory(srcDir, internalCall=True)
        filesReceived = 0
        sizeReceived = 0
        receivedAll = True
        for srcFile in directoryListing["Files"]:
            try:
                filename = os.path.basename(self._urlToPath(srcFile))
                sizeReceived += self._getSingleFile(srcFile, os.path.join(destDir, filename))
                filesReceived += 1
            except Exception:
                receivedAll = False
        for subDir in directoryListing["SubDirs"]:
            try:
                subDirName = os.path.basename(self._urlToPath(subDir).rstrip("/"))
                copyResult = self._getSingleDirectory(subDir, os.path.join(destDir, subDirName))
                filesReceived += copyResult["Files"]
                sizeReceived += copyResult["Size"]
                receivedAll = receivedAll and copyResult["AllGot"]
            except Exception:
                receivedAll = False
        return {"AllGot": receivedAll, "Files": filesReceived, "Size": sizeReceived}

    def putDirectory(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for destDir, sourceDir in res["Value"].items():
            try:
                uploadResult = self._putSingleDirectory(sourceDir, destDir)
                if uploadResult["AllPut"]:
                    successful[destDir] = uploadResult
                else:
                    failed[destDir] = uploadResult
            except Exception:
                failed[destDir] = {"Files": 0, "Size": 0}
        return S_OK({"Failed": failed, "Successful": successful})

    def _putSingleDirectory(self, sourceDir, destDir):
        if not os.path.isdir(sourceDir):
            raise OSError("The supplied source directory does not exist or is not a directory.")
        destRoot = self._urlToPath(destDir)
        allPut = True
        filesPut = 0
        sizePut = 0
        for root, _, files in os.walk(sourceDir):
            relDir = os.path.relpath(root, sourceDir)
            for filename in files:
                localPath = os.path.join(root, filename)
                remotePath = os.path.normpath(os.path.join(destRoot, relDir, filename))
                remoteURL = self._pathToURL(remotePath)
                result = self.putFile({remoteURL: localPath})
                if not result["OK"] or result["Value"]["Failed"]:
                    allPut = False
                    continue
                filesPut += 1
                sizePut += result["Value"]["Successful"][remoteURL]
        return {"AllPut": allPut, "Files": filesPut, "Size": sizePut}

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
        deletedFiles = 0
        deletedSize = 0
        if recursive:
            listing = self._listSingleDirectory(path, internalCall=True)
            for fileURL, metadata in listing["Files"].items():
                self._removeSingleFile(fileURL)
                deletedFiles += 1
                deletedSize += int(metadata.get("Size", 0))
            for subDir in listing["SubDirs"]:
                result = self._removeSingleDirectory(subDir, recursive=True)
                deletedFiles += result["FilesRemoved"]
                deletedSize += result["SizeRemoved"]
        status, _ = self._filesystem().rmdir(self._urlToPath(path))
        if not self._statusOK(status) and not self._isNotFound(status):
            self._ensureOK(status)
        return {"FilesRemoved": deletedFiles, "SizeRemoved": deletedSize}

    def _tapeRestClient(self):
        tapeClient = getattr(self._client(), "TapeRestClient", None)
        if tapeClient is None:
            raise RuntimeError("XRootD TapeRestClient is not available in the installed xrootd bindings")
        proxyLocation = self._proxyLocation() or ""
        return tapeClient(timeout=self.stageTimeout, cert=proxyLocation, key=proxyLocation)

    def _callTapeRestMethod(self, names, *args):
        tapeClient = self._tapeRestClient()
        for name in names:
            method = getattr(tapeClient, name, None)
            if method is not None:
                status, response = method(*args)
                self._ensureOK(status)
                return response
        raise MissingTapeRestMethod(f"XRootD TapeRestClient does not provide any of: {', '.join(names)}")

    def prestageFile(self, path, lifetime=86400):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url in res["Value"]:
            try:
                successful[url] = self._prestageSingleFile(url, lifetime)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _prestageSingleFile(self, path, lifetime):
        try:
            response = self._callTapeRestMethod(("stage", "prestage", "bring_online", "bringOnline"), [path], lifetime)
            return getattr(response, "token", response)
        except MissingTapeRestMethod:
            status, _ = self._filesystem().prepare([self._urlToPath(path)], self._flags().PrepareFlags.STAGE)
            self._ensureOK(status)
            return "xrootd-prepare"

    def prestageFileStatus(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url, token in res["Value"].items():
            try:
                successful[url] = self._prestageSingleFileStatus(url, token)
            except Exception as e:
                failed[url] = repr(e)
        return S_OK({"Failed": failed, "Successful": successful})

    def _prestageSingleFileStatus(self, path, token):
        try:
            response = self._callTapeRestMethod(("stage_status", "prestage_status", "bring_online_poll"), path, token)
            return bool(getattr(response, "staged", response))
        except MissingTapeRestMethod:
            status, archiveInfo = self._tapeRestClient().archive_info([path])
            self._ensureOK(status)
            if not archiveInfo:
                return False
            locality = str(getattr(archiveInfo[0], "locality", "")).upper()
            return "ONLINE" in locality or "DISK" in locality

    def releaseFile(self, path):
        res = checkArgumentFormat(path)
        if not res["OK"]:
            return res
        failed = {}
        successful = {}
        for url, token in res["Value"].items():
            try:
                self._callTapeRestMethod(("release", "evict"), url, str(token))
                successful[url] = str(token)
            except Exception as e:
                failed[url] = f"Error occured while releasing file {repr(e)}"
        return S_OK({"Failed": failed, "Successful": successful})
