from tqdm import tqdm
from collections import defaultdict

from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, ConfigurationOptions

cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True))

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

# Populate the loader with CVE records
loader.load()
cve_freq_by_source = {source: 0 for source in loader.cnas.keys()}
total_cve_freq_by_source = defaultdict(int)

for cve_id, cve in tqdm(loader.records.items(), desc=""):
    total_cve_freq_by_source[cve.source] += 1

    if cve.source not in loader.cnas:
        continue

    cve_freq_by_source[cve.source] += 1

print("CVEs by source (All CNAs)", total_cve_freq_by_source)
print("CVEs by source (Available CNAs)", cve_freq_by_source)
