from pathlib import Path

from nvdutils.data.profiles.basic import BasicProfile
from nvdutils.loaders.json.default import JSONDefaultLoader

loader = JSONDefaultLoader(verbose=True, profile=BasicProfile)

cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

print(f"Loaded {len(cve_dict)} CVEs")