from pathlib import Path

from nvdutils.data.profiles.zero_click import ZeroClickProfile
from nvdutils.loaders.json.default import JSONDefaultLoader

loader = JSONDefaultLoader(verbose=True, profile=ZeroClickProfile)

cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

print(f"Loaded {len(cve_dict)} CVEs")
