import pandas as pd
from tqdm import tqdm
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.configuration import CPEPart
from nvdutils.types.options import CVEOptions, ConfigurationOptions

cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True))

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

# Populate the loader with CVE records
loader.load()

data = []

for cve_id, cve in tqdm(loader.records.items(), desc=""):
    row = {"cve_id": cve_id,
           'vuln_product': len(cve.get_vulnerable_products()),
           'vuln_part': cve.get_vulnerable_parts(ordered=True, values=True, string=True)
           }

    if row['vuln_part'] == 'a::o':
        # most likely only the application is vulnerable in this case
        if len(cve.get_vulnerable_products(part=CPEPart.Application)) == 1:
            row['vuln_part'] = 'a'
            row['vuln_product'] = 1

    data.append(row)

df = pd.DataFrame(data)

single_product_cves = df[df['vuln_product'] == 1]
multi_product_cves = df[df['vuln_product'] > 1]

print("Single-product CVE count:", len(single_product_cves))
print("Single-product parts:", single_product_cves['vuln_part'].value_counts())

print("Multi-product CVE count", len(multi_product_cves))
print("Multi-product parts:", multi_product_cves['vuln_part'].value_counts())
