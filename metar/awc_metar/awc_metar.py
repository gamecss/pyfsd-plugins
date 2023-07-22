"""PyFSD MetarFetcher plugin :: awc_metar.py
Version: 2
"""
from typing import Optional
from urllib.error import ContentTooShortError, HTTPError, URLError
from urllib.request import urlopen

from metar.Metar import Metar
from twisted.plugin import IPlugin
from zope.interface import implementer

from pyfsd.metar.fetch import IMetarFetcher, MetarInfoDict, MetarNotAvailableError


@implementer(IPlugin, IMetarFetcher)
class AWCMetarFetcher:
    metar_source = "aviationweather"

    def fetch(self, _, icao: str) -> Optional[Metar]:
        try:
            with urlopen(
                f"https://beta.aviationweather.gov/cgi-bin/data/metar.php?ids={icao}"
            ) as file:
                lines = file.readlines()
                if not lines:
                    return None
                else:
                    return Metar(
                        lines[0].decode("ascii", "ignore").rstrip("\n"), strict=False
                    )
        except (ContentTooShortError, HTTPError, URLError):
            return None

    def fetchAll(self, _) -> MetarInfoDict:
        try:
            result = {}
            with urlopen(
                "https://beta.aviationweather.gov/cgi-bin/data/metar.php?ids=all"
            ) as file:
                lines = file.readlines()

                for line in lines:
                    metar = Metar(
                        line.decode("ascii", "ignore").rstrip("\n"), strict=False
                    )
                    if metar.station_id is not None:
                        result[metar.station_id] = metar
            return result
        except (ContentTooShortError, HTTPError, URLError):
            raise MetarNotAvailableError


fetcher = AWCMetarFetcher()
