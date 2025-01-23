from nvdutils.loaders.base import CVEDataLoader
from nvdutils.handlers.files.json_reader import JSONReader
from nvdutils.handlers.strategies.by_year import ByYearStrategy

from nvdutils.common.constants import DEFAULT_START_YEAR, DEFAULT_END_YEAR


class JSONYearlyLoader(CVEDataLoader):
    def __init__(self, start: int = DEFAULT_START_YEAR, end: int = DEFAULT_END_YEAR, **kwargs):
        super().__init__(file_reader=JSONReader(), load_strategy=ByYearStrategy(start=start, end=end), **kwargs)
