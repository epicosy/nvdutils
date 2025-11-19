from pathlib import Path
from nvdutils.loaders.json.yearly import JSONYearlyLoader


loader = JSONYearlyLoader()
data_path = Path("~/.nvdutils/nvd-json-data-feeds")

cve = loader.load_by_id("CVE-2017-20006", data_path)

print(cve.configurations.vulnerable_products)
