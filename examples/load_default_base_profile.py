from pathlib import Path
from nvdutils.loaders.json.default import JSONDefaultLoader

from collections import defaultdict

loader = JSONDefaultLoader(verbose=True)
statuses = defaultdict(int)

for el in loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True):
    statuses[el.status.name] += 1

print(statuses)
