from tqdm import tqdm
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions
from nvdutils.types.configuration import CPEPart

cve_options = CVEOptions()

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds',
                         options=cve_options,
                         verbose=True)

# Populate the loader with CVE records
loader.load()

data = []
not_platform_specific = 0
platform_specific = 0

for cve_id, cve in tqdm(loader.records.items(), desc=""):
    if len(cve.configurations) == 0:
        continue

    if cve.is_platform_specific(is_part=CPEPart.Application):
        platform_specific += 1
    else:
        not_platform_specific += 1


print(f"Number of platform dependent CVEs: {platform_specific}")
print(f"Number of platform independent CVEs: {not_platform_specific}")
