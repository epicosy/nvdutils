from collections import defaultdict
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions

cve_options = CVEOptions()

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds',
                         options=cve_options,
                         verbose=True)

# Populate the loader with CVE records
loader.load()

tgt_sw = defaultdict(int)
vendor_product_pairs = set()
app_specific_cves = 0
has_target_sw = 0
platform_specific_cves = 0

for cve_id, cve in loader.records.items():
    is_app_specific = True
    is_platform_specific = False

    vendor_product_tgt_sw = defaultdict(lambda: defaultdict(int))

    for configuration in cve.configurations:
        if not is_app_specific:
            break

        for node in configuration.nodes:
            if not is_app_specific:
                break

            for cpe_match in node.cpe_match:
                if not cpe_match.vulnerable:
                    continue

                if cpe_match.cpe.part != 'a':
                    is_app_specific = False
                    break

                if cpe_match.cpe.target_sw in ['*', '-']:
                    continue

                vendor_product = f"{cpe_match.cpe.vendor}::{cpe_match.cpe.product}"
                vendor_product_tgt_sw[vendor_product][cpe_match.cpe.target_sw] += 1

                if cpe_match.is_platform_specific_sw:
                    is_platform_specific = cpe_match.is_platform_specific_sw

    if not is_app_specific:
        continue

    app_specific_cves += 1

    if len(vendor_product_tgt_sw) == 0:
        continue

    has_target_sw += 1

    if is_platform_specific:
        platform_specific_cves += 1

    for vendor_product, target_sw in vendor_product_tgt_sw.items():
        vendor_product_pairs.add(vendor_product)
        for sw, _ in target_sw.items():
            # count only once per vendor-product
            tgt_sw[sw] += 1


print(len(vendor_product_pairs), dict(tgt_sw))
print(f"App specific CVEs: {app_specific_cves}")
print(f"CVEs with target SW: {has_target_sw}")
print(f"Platform specific CVEs: {platform_specific_cves}")
