from enum import Enum
from tqdm import tqdm
from typing import Tuple, Union
from pathlib import Path

from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.core.loaders.cna.base import CNABaseLoader
from nvdutils.types.options import CVEOptions, ConfigurationOptions, CPEPart


class LicenseModel(Enum):
    OpenSource = 1
    Commercial = 2
    Unknown = 3


class MatchType(Enum):
    Vendor = 1
    Owner = 2
    VendorOwner = 3


def get_license_model(target_cve, cve_owners, cve_vendors, vuln_products_count, target_owners, target_vendors)\
        -> Tuple[LicenseModel, Union[MatchType, None]]:
    overlap_owners = cve_owners.intersection(target_owners)
    all_vendors_names = list(target_vendors.keys())
    # Adds aliases
    all_vendors_names.extend([a for v in target_vendors.values() if v.aliases for a in v.aliases])
    overlap_vendors = cve_vendors.intersection(target_vendors.keys())
    overlap_owners_vendors = cve_owners.intersection(cve_vendors)

    if len(overlap_owners_vendors) > 0:
        return LicenseModel.OpenSource, MatchType.VendorOwner

    elif len(overlap_owners) > 0:
        return LicenseModel.OpenSource, MatchType.Owner

    elif len(overlap_vendors) > 0:
        os_and_app_vuln = None

        if vuln_products_count > 1 and target_cve.is_part_specific(CPEPart.Application):
            # When there's only one vulnerable application
            # to cover the cases where there are multiple OS vendors and a single vulnerable app
            vuln_parts = target_cve.get_vulnerable_parts(values=True)

            if len(vuln_parts) == 2 and CPEPart.Application.value in vuln_parts and CPEPart.OS.value in vuln_parts:
                os_and_app_vuln = next(iter(target_cve.get_vulnerable_products(CPEPart.Application)))

        for vendor_name in overlap_vendors:
            vendor = target_vendors[vendor_name]

            if not vendor.is_vendor() and vendor.is_open_source():
                if os_and_app_vuln and vendor_name != os_and_app_vuln.vendor:
                    continue
                return LicenseModel.OpenSource, MatchType.Vendor
        else:
            return LicenseModel.Commercial, MatchType.Vendor
    else:
        return LicenseModel.Unknown, None

    # TODO: define condition for checking the vendors within other CNAs scope, i.e., when current CNAs points to
    #  other CNAs; for instance, Red Hat points to vendors with open source projects, only that kind of scope should
    #  be considered when performing the assignment; and should be performed after the other checks;


precise_bugs_cves = [path.stem for path in Path('/tmp/PreciseBugs/CVEs').iterdir() if path.is_dir() and 'CVE' in path.name]

cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True))

cna_loader = CNABaseLoader()
loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

# Populate the loader with CVE records
loader.load()

cna_vendor_cve = 0
mitre_cna_vendor_cve = 0
cna_vendor_match = 0
cna_open_source_match = 0
cve_is_in_open_source = 0
cve_is_in_vendor = 0
cve_is_in_unknown = 0

commercial_cves = []
open_source_cves = []

all_vendors = {k: v for cna in cna_loader.records.values() for k, v in cna.scope.organizations.items()}
all_owners = [k for cna in cna_loader.records.values() for k in cna.get_owners(lower=True)]


for cve_id, cve in tqdm(loader.records.items(), desc=""):
    if cve.source in cna_loader.records:
        cna_vendor_cve += 1
    elif cve.source == "cve@mitre.org":
        mitre_cna_vendor_cve += 1
    else:
        continue

    vuln_products = cve.get_vulnerable_products()

    vendors = set()
    owners = set()

    for commit in cve.get_commit_references(vcs='github'):
        owners.add(commit.owner)
        owners.add(f"{commit.owner}_project")
        owners.add(f"{commit.owner}project")

    for product in vuln_products:
        vendors.add(product.vendor)

    # TODO: DETERMINE WHAT TO DO WITH SERVICES
    if cve.source == "cve@mitre.org":
        license_model, match_type = get_license_model(cve, owners, vendors, vuln_products_count=len(vuln_products),
                                                      target_vendors=all_vendors,
                                                      target_owners=all_owners)
    else:
        license_model, match_type = get_license_model(cve, owners, vendors, vuln_products_count=len(vuln_products),
                                                      target_vendors=cna_loader.records[cve.source].scope.organizations,
                                                      target_owners=cna_loader.records[cve.source].get_owners(lower=True))

    if match_type in [MatchType.VendorOwner, MatchType.Owner]:
        cna_open_source_match += 1

    if match_type == MatchType.Vendor:
        cna_vendor_match += 1

    if license_model == LicenseModel.OpenSource:
        cve_is_in_open_source += 1
        open_source_cves.append(cve_id)
    elif license_model == LicenseModel.Commercial:
        cve_is_in_vendor += 1
        commercial_cves.append(cve_id)
    else:
        cve_is_in_unknown += 1

print(f"CVEs with CNA vendor: {cna_vendor_cve}")
print(f"CVEs with MITRE CNA vendor: {mitre_cna_vendor_cve}")
print(f"CVEs with CNA open source match: {cna_open_source_match}")
print(f"CVEs with CNA vendor match: {cna_vendor_match}")
print(f"CVEs in open source projects: {cve_is_in_open_source}")
print(f"CVEs in commercial product: {cve_is_in_vendor}")
print(f"CVEs in unknown software: {cve_is_in_unknown}")

print(f"Overlap open source and precise bugs: {len(set(open_source_cves).intersection(precise_bugs_cves))}")
