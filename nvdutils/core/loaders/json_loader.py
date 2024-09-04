import json

from pathlib import Path

from nvdutils.types.options import CVEOptions
from nvdutils.core.loaders.base import CVEDataLoader


class JSONFeedsLoader(CVEDataLoader):
    def __init__(self, data_path, options: CVEOptions, **kwargs):
        super().__init__(data_path, options, **kwargs)

    @staticmethod
    def load_cve(path: str) -> dict:
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")
        if path.suffix != '.json':
            raise ValueError(f"{path} is not a json file")
        if path.stat().st_size == 0:
            raise ValueError(f"{path} is empty")

        # read contents of the file
        with path.open('r') as f:
            cve_data = json.load(f)

        return cve_data

    def get_cve_path(self, cve_id: str):
        _, year, number = cve_id.split('-')

        cve_year = f"CVE-{year}"
        length = len(number)

        # Use a range check for better clarity
        if 4 <= length <= 7:
            path = self.data_path / cve_year / f"{cve_year}-{number[:length - 2]}xx" / f"{cve_id}.json"

            if path.exists():
                return path

        raise FileNotFoundError(f"Path for {cve_id} not found")

    def get_cve_ids_by_year(self, year: int) -> list:
        nvd_database_year_path = self.data_path / f"CVE-{year}"

        for path in nvd_database_year_path.iterdir():
            if path.is_dir():
                for cve in path.iterdir():
                    if cve.is_file():
                        yield cve.stem
