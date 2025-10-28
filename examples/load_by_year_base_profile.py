from pathlib import Path
from nvdutils.loaders.json.yearly import JSONYearlyLoader

from collections import defaultdict

loader = JSONYearlyLoader(verbose=True, start=2023, end=2023)
statuses = defaultdict(int)
tags = defaultdict(int)

for el in loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True):
    statuses[el.status.name] += 1
    cve_tags = el.tags.unique(True)

    for tag in cve_tags:
        tags[tag] += 1

print(statuses)
print(tags)
