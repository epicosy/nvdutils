from nvdutils.loaders.base import CVEDataLoader
from nvdutils.handlers.files.json_reader import JSONReader


class JSONDefaultLoader(CVEDataLoader):
    def __init__(self, **kwargs):
        super().__init__(file_reader=JSONReader(), **kwargs)
