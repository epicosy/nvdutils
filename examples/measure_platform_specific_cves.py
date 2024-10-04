import pandas as pd

from tqdm import tqdm
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, ConfigurationOptions
from nvdutils.types.configuration import CPEPart

cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True))

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

# Populate the loader with CVE records
loader.load()

data = []
not_platform_specific = 0
platform_specific = 0

for cve_id, cve in tqdm(loader.records.items(), desc=""):
    by_runtime, by_tgt_sw, by_tgt_hw = cve.is_platform_specific(part=CPEPart.Application)
    is_platform_specific = by_runtime or by_tgt_sw or by_tgt_hw

    if is_platform_specific:
        platform_specific += 1
    else:
        not_platform_specific += 1

    data.append({'cve_id': cve_id, 'platform_specific': is_platform_specific, 'runtime': by_runtime,
                 'tgt_sw': by_tgt_sw, 'tgt_hw': by_tgt_hw})

df = pd.DataFrame(data)

print(f"Number of platform dependent CVEs: {platform_specific}")
print(f"Number of platform independent CVEs: {not_platform_specific}")
print(f"runtime: {len(df[df['runtime']])}")
print(f"tgt_sw: {len(df[df['tgt_sw']])}")
print(f"tgt_hw: {len(df[df['tgt_hw']])}")
print(f"Overlaps:\n{df[['runtime', 'tgt_sw', 'tgt_hw']].value_counts()}")
