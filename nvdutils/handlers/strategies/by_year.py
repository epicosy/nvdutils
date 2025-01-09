from tqdm import tqdm
from pathlib import Path

from nvdutils.data.collections.dictionaries.yearly_dictionary import CVEYearlyDictionary
from nvdutils.handlers.strategies.base import LoadStrategy


class ByYearStrategy(LoadStrategy):
    def __call__(self, data_loader, data_path: Path, *args, **kwargs) -> CVEYearlyDictionary:
        # TODO: specify data_loader type and avoid circular imports
        cve_dict = CVEYearlyDictionary()

        for year in tqdm(data_loader.filters.time_range, desc="Processing CVE records by year", unit='year'):
            year_data_path = data_path.expanduser() / f"CVE-{year}"

            if not year_data_path.is_dir():
                print(f"Year {year} not found")
                continue

            for cve in list(data_loader(data_path=year_data_path, include_subdirectories=True)):
                # TODO: decide if should get CVE_Dictionary from super load method and add as entry to cve_dict
                cve_dict.add_entry(cve)

        return cve_dict
