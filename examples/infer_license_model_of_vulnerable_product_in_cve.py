from tqdm import tqdm

from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, ConfigurationOptions

cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True))

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

# Populate the loader with CVE records
loader.load()

cna_vendor_cve = 0
cna_vendor_match = 0
cna_open_source_match = 0
cve_is_in_open_source = 0
cve_is_in_vendor = 0
cve_is_in_unknown = 0


for cve_id, cve in tqdm(loader.records.items(), desc=""):
    if cve.source not in loader.cnas:
        continue

    cna_vendor_cve += 1

    vuln_products = cve.get_vulnerable_products()

    vendors = set()
    owners = set()

    for commit in cve.get_commit_references(vcs='github'):
        owners.add(commit.owner)

    for product in vuln_products:
        vendors.add(product.vendor)

    overlap_vendors = vendors.intersection(loader.cnas[cve.source].scope.keys())
    overlap_owners = owners.intersection(loader.cnas[cve.source].get_owners())

    if overlap_owners:
        cna_open_source_match += 1
        cve_is_in_open_source += 1

    elif overlap_vendors:
        cna_vendor_match += 1

        for vendor_name in overlap_vendors:
            vendor = loader.cnas[cve.source].scope[vendor_name]
            if not vendor.is_vendor() and vendor.is_open_source():
                cve_is_in_open_source += 1
                break
        else:
            cve_is_in_vendor += 1
    else:
        cve_is_in_unknown += 1

print(f"CVEs with CNA vendor: {cna_vendor_cve}")
print(f"CVEs with CNA open source match: {cna_open_source_match}")
print(f"CVEs with CNA vendor match: {cna_vendor_match}")
print(f"CVEs in open source projects: {cve_is_in_open_source}")
print(f"CVEs in commercial product: {cve_is_in_vendor}")
print(f"CVEs in unknown software: {cve_is_in_unknown}")
