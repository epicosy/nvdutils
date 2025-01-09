from nvdutils.loaders.base import CVEDataLoader
from nvdutils.handlers.files.json_reader import JSONReader
from nvdutils.handlers.strategies.by_year import ByYearStrategy


class JSONYearlyLoader(CVEDataLoader):
    def __init__(self, **kwargs):
        super().__init__(file_reader=JSONReader(), load_strategy=ByYearStrategy(), **kwargs)
