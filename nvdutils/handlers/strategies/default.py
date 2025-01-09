from pathlib import Path

from nvdutils.data.collections.dictionaries.dictionary import CVEDictionary
from nvdutils.handlers.strategies.base import LoadStrategy


class DefaultStrategy(LoadStrategy):
    def __call__(self, data_loader, data_path: Path, *args, **kwargs) -> CVEDictionary:
        # TODO: specify data_loader type and avoid circular imports

        cve_dict = CVEDictionary()

        for cve in data_loader(data_path=data_path, include_subdirectories=True):
            cve_dict.add_entry(cve)

        return cve_dict
