import pandas as pd
from tqdm import tqdm
from collections import defaultdict
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=CVEOptions(), verbose=True)

# Populate the loader with CVE records
loader.load()

part_in_vendor_product_pairs = defaultdict(lambda: defaultdict(int))
cve_in_vendor_product_pairs = defaultdict(set)
print("Loaded CVEs:", len(loader.records))

for cve_id, cve in tqdm(loader.records.items(), desc="Aggregating parts in vendor-product pairs"):
    products = cve.get_products()

    for product in products:
        key = f"{product.vendor}::{product.name}"
        part_in_vendor_product_pairs[key][product.part.value] += 1
        cve_in_vendor_product_pairs[key].add(cve_id)

print("Total Unique Products", len(part_in_vendor_product_pairs))

# Transform the dictionary into a list of dictionaries
data = []
single_part_cve = set()
multi_part_cve = set()

for vendor_product, parts in tqdm(part_in_vendor_product_pairs.items(), desc="Transforming data"):
    vendor, product = vendor_product.split("::")
    row = {"vendor": vendor, "product": product}
    row.update(parts)
    row['parts'] = len(parts)

    if len(parts) > 1:
        # sort the keys to ensure the order is consistent and concatenate them
        row['type'] = "::".join(sorted(parts.keys()))
        multi_part_cve.update(cve_in_vendor_product_pairs[vendor_product])
    else:
        row['type'] = list(parts.keys())[0]
        single_part_cve.update(cve_in_vendor_product_pairs[vendor_product])

    row['total'] = sum(parts.values())
    data.append(row)


print("Single-part CVEs", len(single_part_cve))
print("Multi-part CVEs", len(multi_part_cve))

# Create the DataFrame
df = pd.DataFrame(data)

# keep only the vendor-product pairs with more than one part
multi_part_products = df[df['parts'] > 1]
single_part_products = df[df['parts'] == 1]

print("Single-part products counts:", len(single_part_products))
print("Single-part products:", single_part_products['type'].value_counts())

print("Multi-part products counts:", len(multi_part_products))
print("Multi-part products:", multi_part_products['type'].value_counts())

print(multi_part_products[multi_part_products['type'].isin(['a::o', 'a::h'])][['vendor', 'product']])
