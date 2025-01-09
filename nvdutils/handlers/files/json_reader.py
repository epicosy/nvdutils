import json

from pathlib import Path

from nvdutils.handlers.files.base import FileReader


class JSONReader(FileReader):
    def __init__(self, **kwargs):
        super().__init__(extension='.json', **kwargs)
        # Path('~/.nvdutils/nvd-json-data-feeds')

    def __call__(self, path: Path) -> dict:
        # read contents of the file
        with path.open('r') as f:
            cve_data = json.load(f)

        return cve_data
