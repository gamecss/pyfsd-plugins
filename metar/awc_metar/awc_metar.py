"""PyFSD MetarFetcher plugin :: awc_metar.py
Version: 3
"""
from csv import reader
from datetime import date
from gzip import decompress
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
                "https://beta.aviationweather.gov/data/cache/metars.cache.csv.gz"
            ) as file:
                decoded_lines = (
                    decompress(file.read()).decode("ascii", "ignore").splitlines()
                )
                for code, station, time, *_ in reader(decoded_lines[6:]):
                    dt = date.fromisoformat(time.split("T")[0])
                    result[station] = Metar(
                        code, strict=False, month=dt.month, year=dt.year
                    )
            return result
        except (ContentTooShortError, HTTPError, URLError):
            raise MetarNotAvailableError


fetcher = AWCMetarFetcher()
