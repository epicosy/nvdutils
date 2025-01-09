from pathlib import Path
from nvdutils.loaders.json.yearly import JSONYearlyLoader

from collections import defaultdict

loader = JSONYearlyLoader(verbose=True)
statuses = defaultdict(int)

for el in loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True):
    statuses[el.status.name] += 1

print(statuses)
