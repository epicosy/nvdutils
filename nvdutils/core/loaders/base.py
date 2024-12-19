import json
import pandas as pd

from tqdm import tqdm
from typing import List
from pathlib import Path
from abc import abstractmethod
from datetime import datetime

from nvdutils.types.options import CVEOptions
from nvdutils.types.cve import CVE, Description
from nvdutils.types.stats import LoaderYearlyStats
from nvdutils.core.parse import parse_weaknesses, parse_metrics, parse_configurations, parse_references


# TODO: use pydantic for parsing
NVD_JSON_KEYS = ['id', 'descriptions', 'references', 'metrics', 'references']


class CVEDataLoader:
    def __init__(self, data_path: str, options: CVEOptions, verbose: bool = False):
        self.verbose = verbose
        self.data_path = Path(data_path).expanduser()

        # check if the data path exists
        if not self.data_path.exists():
            raise FileNotFoundError(f"{self.data_path} not found")

        self.options = options
        self.stats = {year: LoaderYearlyStats(year) for year in range(self.options.start, self.options.end + 1)}
        self.records = {}

    def load(self, by_year: bool = False, eager: bool = True, cve_ids: List[str] = None):
        """
            Main entry point for loading the CVE records. Can store data grouped by year if specified.
        """

        if cve_ids:
            for cve_id in tqdm(cve_ids):
                if cve_id in self.records:
                    self._log(f"{cve_id} already processed")
                    continue

                cve = self._load_and_parse_cve(cve_id)
                options_check = self.options.check(cve)

                if cve is None or not options_check():
                    continue

                self._store_cve(cve, year=None, cve_id=cve_id, by_year=False)

                if not eager:
                    yield cve_id, cve

        else:
            for year in tqdm(self.stats.keys(), desc="Processing metadata of CVE records by year", unit='year'):
                self._process_year(year, by_year)
                self._print_stats(year)

                if by_year and not eager:
                    yield year, self.records[year]

    def _process_year(self, year: int, by_year: bool):
        """
            Process the CVE records for the given year, optionally storing them in a year-specific dictionary.
        """

        if by_year:
            self.records[year] = {}

        cve_ids = list(self.get_cve_ids_by_year(year))
        self.stats[year].total = len(cve_ids)

        for cve_id in tqdm(cve_ids, leave=False):
            if cve_id in self.records:
                self._log(f"{cve_id} already processed")
                continue

            cve = self._load_and_parse_cve(cve_id)
            options_check = self.options.check(cve)
            self.stats[year].update_details_with_checks(options_check)

            if cve is None or not options_check():
                self.stats[year].skipped += 1
                continue

            self._store_cve(cve, year, cve_id, by_year)
            self.stats[year].processed += 1

    def _load_and_parse_cve(self, cve_id: str) -> CVE:
        """
            Load and parse the CVE data for the given CVE ID.
        """
        cve_path = self.get_cve_path(cve_id)
        cve_dict = self.load_cve(cve_path)

        return self.parse_cve_data(cve_dict)

    def _store_cve(self, cve: CVE, year: int, cve_id: str, by_year: bool):
        """
            Stores the CVE record in the appropriate structure depending on whether by_year is set.
        """
        if by_year:
            self.records[year][cve_id] = cve
        else:
            self.records[cve_id] = cve

    def _print_stats(self, year: int):
        """
            Print the statistics for the given year.
        """
        self._log(json.dumps(self.stats[year].to_dict(), indent=4))

    def _log(self, message: str):
        """
            Log the message if verbose is set.
        """
        if self.verbose:
            print(message)

    @staticmethod
    def parse_cve_data(cve_data: dict) -> CVE:
        # check if the cve_data is a dictionary
        if not isinstance(cve_data, dict):
            raise ValueError(f"provided data is not a dictionary")

        # check if the file has the expected keys
        if not all(key in cve_data for key in NVD_JSON_KEYS):
            raise ValueError(f"provided data does not have the expected keys")

        cve_id = cve_data['id']
        published_date = datetime.strptime(cve_data['published'], "%Y-%m-%dT%H:%M:%S.%f")
        last_modified_date = datetime.strptime(cve_data['lastModified'], "%Y-%m-%dT%H:%M:%S.%f")
        descriptions = [Description(**desc) for desc in cve_data['descriptions']]
        source = cve_data.get('sourceIdentifier', None)
        weaknesses = parse_weaknesses(cve_data['weaknesses']) if 'weaknesses' in cve_data else {}
        metrics = parse_metrics(cve_data['metrics']) if 'metrics' in cve_data else []
        configurations = parse_configurations(cve_data['configurations']) if 'configurations' in cve_data else []
        references = parse_references(cve_data['references']) if 'references' in cve_data else []

        cve = CVE(id=cve_id, source=source, published_date=published_date, last_modified_date=last_modified_date,
                  status=cve_data.get('vulnStatus', None), weaknesses=weaknesses, metrics=metrics,
                  configurations=configurations, descriptions=descriptions, references=references)

        return cve

    @abstractmethod
    def get_cve_ids_by_year(self, year) -> List[str]:
        pass

    @staticmethod
    @abstractmethod
    def load_cve(path: str) -> dict:
        pass

    @abstractmethod
    def get_cve_path(self, cve_id: str):
        pass

    def __len__(self):
        return len(self.records)

    def __str__(self):
        df = pd.DataFrame([stats.to_dict() for stats in self.stats.values()])
        return df.to_string(index=False)
