""".. class:: CTAStorage

Plugin to interact with CERN CTA and WLCG Tape REST endpoints.
"""
from DIRAC import gLogger
from DIRAC.Resources.Storage.XROOTStorage import XROOTStorage

sLog = gLogger.getSubLogger(__name__)


class CTAStorage(XROOTStorage):
    """Plugin to interact with CERN CTA and WLCG Tape REST compliant tape endpoints.

    It is XROOT with added tape capabilities via the WLCG Tape REST API.
    Since CTA supports ONLY xroot, do not forget to add
    xroot in your `Operations/DataManagement/RegistrationProtocols` list

    Configuration example::

        StorageElements
        {
          CTA-PPS
          {
            BackendType = Cta
            AccessProtocols = root
            WriteProtocols = root
            # This is very important if you have to stage with this protocol, but might transfer
            # using a different protocol, like https
            StageProtocols = root
            SEType = T1D0
            SpaceReservation = LHCb-Tape
            OccupancyLFN = /eos/ctalhcbpps/proc/accounting
            OccupancyPlugin = WLCGAccountingJson
            # Config for this plugin is below
            ###################################
            CTA
            {
              Host = eosctalhcbpps.cern.ch
              Protocol = root
              Path = /eos/ctalhcbpps/archivetest/
              Access = remote
            }
          }
        }
    """

    def __init__(self, storageName, parameters):
        """c'tor

        :param self: self reference
        :param str storageName: SE name
        :param dict parameters: passed to parent's class
        """
        super().__init__(storageName, parameters)
        self.log = sLog.getSubLogger(storageName)
        self.pluginName = "CTA"
        self._defaultExtendedAttributes = ["user.status"]

    def _fetchTapeArchiveInfo(self, urls):
        """Fetch tape archive info for a list of URLs via the WLCG Tape REST API."""
        tapeInfo = {}
        try:
            status, infos = self._tapeClient().archive_info(list(urls))
            if self._statusOK(status):
                for info in infos:
                    key = getattr(info, "url", getattr(info, "path", None))
                    if key:
                        tapeInfo[key] = info
        except Exception as e:
            self.log.debug(f"Could not retrieve tape archive info: {e!r}")
        return tapeInfo

    def _enrichMetadata(self, metadata, url, tapeInfo=None):
        """Enrich file metadata with tape locality attributes."""
        if not tapeInfo:
            return
        info = tapeInfo.get(url)
        if info is not None:
            if getattr(info, "error", None):
                self.log.debug(f"Tape archive info error for {url}: {info.error}")
            else:
                self._updateMetadataDict(metadata, {"locality": getattr(info, "locality", None)})

    def _updateMetadataDict(self, metadataDict, attributeDict):
        """Updating the metadata dictionary with tape specific attributes

        :param dict metadataDict: metadataDict to add tape specific attributes to
        :param dict attributeDict: contains 'locality' or 'user.status'
        """
        locality = attributeDict.get("locality") or attributeDict.get("user.status", "")
        if locality == "DISK_AND_TAPE" or "ONLINE_AND_NEARLINE" in locality:
            metadataDict["Cached"] = 1
            metadataDict["Migrated"] = 1
            metadataDict["Lost"] = 0
            metadataDict["Unavailable"] = 0
            metadataDict["Accessible"] = True
            metadataDict["user.status"] = "ONLINE_AND_NEARLINE"
        elif locality == "TAPE" or "NEARLINE" in locality:
            metadataDict["Cached"] = 0
            metadataDict["Migrated"] = 1
            metadataDict["Lost"] = 0
            metadataDict["Unavailable"] = 0
            metadataDict["Accessible"] = False
            metadataDict["user.status"] = "NEARLINE"
        elif locality == "DISK" or "ONLINE" in locality:
            metadataDict["Cached"] = 1
            metadataDict["Migrated"] = 0
            metadataDict["Lost"] = 0
            metadataDict["Unavailable"] = 0
            metadataDict["Accessible"] = True
            metadataDict["user.status"] = "ONLINE"
        elif locality == "LOST":
            metadataDict["Cached"] = 0
            metadataDict["Migrated"] = 0
            metadataDict["Lost"] = 1
            metadataDict["Unavailable"] = 0
            metadataDict["Accessible"] = False
            metadataDict["user.status"] = "LOST"
        elif locality == "UNAVAILABLE":
            metadataDict["Cached"] = 0
            metadataDict["Migrated"] = 0
            metadataDict["Lost"] = 0
            metadataDict["Unavailable"] = 1
            metadataDict["Accessible"] = False
            metadataDict["user.status"] = "UNAVAILABLE"
