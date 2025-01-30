from pathlib import Path
from nvdutils.loaders.json.yearly import JSONYearlyLoader


loader = JSONYearlyLoader()
data_path = Path("~/.nvdutils/nvd-json-data-feeds")

cve = loader.load_by_id("CVE-2015-5334", data_path)

print(cve)
