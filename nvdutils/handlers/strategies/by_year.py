from tqdm import tqdm
from pathlib import Path

from nvdutils.handlers.strategies.base import LoadStrategy
from nvdutils.common.constants import DEFAULT_START_YEAR, DEFAULT_END_YEAR
from nvdutils.data.collections.dictionaries.yearly_dictionary import CVEYearlyDictionary


class ByYearStrategy(LoadStrategy):
    def __init__(self, start: int = DEFAULT_START_YEAR, end: int = DEFAULT_END_YEAR):
        self.start = start
        self.end = end

    @property
    def time_range(self):
        return range(self.start, self.end + 1)

    def __call__(self, data_loader, data_path: Path, *args, **kwargs) -> CVEYearlyDictionary:
        # TODO: specify data_loader type and avoid circular imports
        cve_dict = CVEYearlyDictionary()

        for year in tqdm(self.time_range, desc="Processing CVE records by year", unit='year'):
            year_data_path = data_path.expanduser() / f"CVE-{year}"

            if not year_data_path.is_dir():
                print(f"Year {year} not found")
                continue

            for cve in list(data_loader(data_path=year_data_path, include_subdirectories=True)):
                # TODO: decide if should get CVE_Dictionary from super load method and add as entry to cve_dict
                cve_dict.add_entry(cve)

        return cve_dict
