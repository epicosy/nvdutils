import pandas as pd
import json

from tqdm import tqdm
from typing import List
from pathlib import Path
from abc import abstractmethod

from nvdutils.types.cve import CVE
from nvdutils.types.options import CVEOptions
from nvdutils.types.stats import LoaderYearlyStats
from nvdutils.core.parse import parse_cna


class CVEDataLoader:
    def __init__(self, data_path: str, options: CVEOptions, cna_data_path: str = '~/.nvdutils/cna-list/cnas',
                 verbose: bool = False):
        self.verbose = verbose
        self.data_path = Path(data_path).expanduser()
        self._cnas = {}

        # check if the data path exists
        if not self.data_path.exists():
            raise FileNotFoundError(f"{self.data_path} not found")

        cnd_data_path = Path(cna_data_path).expanduser()

        # check if the CNA data path exists
        if not cnd_data_path.exists():
            raise FileNotFoundError(f"{cnd_data_path} not found")

        for cna_file in tqdm(cnd_data_path.iterdir(), desc="Loading CNA data", unit='file'):
            with cna_file.open('r') as f:
                cna_json = json.load(f)
                cna = parse_cna(cna_file.stem, cna_json)
                self._cnas[cna.email] = cna

        self.options = options
        self.stats = {year: LoaderYearlyStats(year) for year in range(self.options.start, self.options.end + 1)}
        self.records = {}

    @property
    def cnas(self):
        return self._cnas

    def load(self):
        for year in tqdm(self.stats.keys(), desc="Processing metadata of CVE records by year", unit='year'):
            cve_ids = list(self.get_cve_ids_by_year(year))
            self.stats[year].total = len(cve_ids)

            for cve_id in cve_ids:
                if cve_id not in self.records:
                    cve_path = self.get_cve_path(cve_id)
                    cve = self.load_cve(cve_path)

                    if not self._check_filters(cve, self.stats[year]):
                        continue

                    self.records[cve_id] = cve
                else:
                    print(f"{cve_id} already processed")

            if self.verbose:
                print(self.stats[year].to_dict())

    def _check_filters(self, cve: CVE, stats: LoaderYearlyStats):
        if self.options.cna_options.emails and cve.source not in self.options.cna_options.emails:
            # TODO: implement the stats count for this condition
            return False

        if self.options.cna_options.root_emails and self.cnas[cve.source].root not in self.options.cna_options.root_emails:
            # TODO: implement the stats count for this condition
            return False

        if not cve.is_valid():
            stats.rejected += 1
            return False

        if not cve.has_weaknesses():
            stats.no_weaknesses += 1

        if self.options.config_options.has_config and len(cve.configurations) == 0:
            stats.no_config_info += 1
            return False

        if self.options.config_options.has_vulnerable_products and len(cve.get_vulnerable_products()) == 0:
            stats.no_vuln_products += 1
            return False

        if self.options.cwe_options.has_cwe:
            if not cve.has_cwe(in_primary=self.options.cwe_options.in_primary,
                               in_secondary=self.options.cwe_options.in_secondary,
                               is_single=self.options.cwe_options.is_single,
                               cwe_id=self.options.cwe_options.cwe_id):
                # TODO: the stats count for this condition needs to be improved
                stats.no_cwe_info += 1
                return False

        if self.options.cvss_options.has_v3 and not cve.has_cvss_v3():
            stats.no_cvss_v3 += 1
            return False

        if (self.options.config_options.is_single_vuln_product and
                not cve.is_single_vuln_product(self.options.config_options.vuln_product_is_part)):
            stats.other += 1
            return False

        if self.options.desc_options.is_single_vuln and cve.has_multiple_vulnerabilities():
            stats.multi_vuln += 1
            return False

        if self.options.desc_options.is_single_component and cve.has_multiple_components():
            stats.multi_component += 1
            return False

        return True

    @abstractmethod
    def get_cve_ids_by_year(self, year) -> List[str]:
        pass

    @staticmethod
    @abstractmethod
    def load_cve(path: str) -> CVE:
        pass

    @abstractmethod
    def get_cve_path(self, cve_id: str):
        pass

    def __len__(self):
        return len(self.records)

    def __str__(self):
        df = pd.DataFrame([stats.to_dict() for stats in self.stats.values()])
        return df.to_string(index=False)
