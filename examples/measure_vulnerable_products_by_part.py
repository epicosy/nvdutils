import pandas as pd
from tqdm import tqdm
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, CWEOptions, CVSSOptions, DescriptionOptions, ConfigurationOptions

cve_options = CVEOptions(
    cwe_options=CWEOptions(),
    cvss_options=CVSSOptions(),
    desc_options=DescriptionOptions(),
    config_options=ConfigurationOptions()
)

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds',
                         options=cve_options,
                         verbose=True)

# Populate the loader with CVE records
loader.load()

data = []

for cve_id, cve in tqdm(loader.records.items(), desc=""):
    row = {"cve_id": cve_id,
           'vuln_product': len(cve.get_vulnerable_products()),
           'vuln_part': cve.get_vulnerable_parts(ordered=True, values=True, string=True)
           }

    data.append(row)

df = pd.DataFrame(data)

no_product_cves = df[df['vuln_product'] == 0]
single_product_cves = df[df['vuln_product'] == 1]
multi_product_cves = df[df['vuln_product'] > 1]

print("No-product CVE count:", len(no_product_cves))

print("Single-product CVE count:", len(single_product_cves))
print("Single-product parts:", single_product_cves['vuln_part'].value_counts())

print("Multi-product CVE count", len(multi_product_cves))
print("Multi-product parts:", multi_product_cves['vuln_part'].value_counts())
