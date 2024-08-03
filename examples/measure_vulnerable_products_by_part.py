import pandas as pd
from tqdm import tqdm
from collections import defaultdict
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
    row = {"cve_id": cve_id}
    vuln_products = cve.get_vulnerable_products()

    if cve.is_single_vuln_product():
        row['vuln_product'] = 1
        row['vuln_part'] = list(vuln_products)[0].part.value
    elif len(vuln_products) == 0:
        row['vuln_product'] = 0
        row['vuln_part'] = None
    else:
        row['vuln_product'] = len(vuln_products)
        row['vuln_part'] = "::".join(sorted(set(product.part.value for product in vuln_products)))

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
