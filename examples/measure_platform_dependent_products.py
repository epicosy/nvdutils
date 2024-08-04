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
    row = {"cve_id": cve_id, "platform_dependent": 0, "platform_independent": 0, "platform_specific": False}

    if len(cve.configurations) == 0:
        continue

    parts = set()

    for configuration in cve.configurations:
        vuln_products = configuration.get_vulnerable_products()

        if len(vuln_products) == 0:
            continue

        if configuration.is_platform_specific():
            row["platform_dependent"] += 1

            for vp in vuln_products:
                parts.add(vp.part.value)
        else:
            row["platform_independent"] += 1

    if row["platform_dependent"] > row["platform_independent"]:
        row["platform_specific"] = True
        row['parts'] = "::".join(sorted(parts))

    data.append(row)

df = pd.DataFrame(data)
platform_dependent_df = df[df["platform_specific"]]
platform_independent_df = df[~df["platform_specific"]]

print(f"Number of platform dependent CVEs: {len(platform_dependent_df)}")
print(f"Number of platform independent CVEs: {len(platform_independent_df)}")
print(f"Platform specific CVEs by parts: {platform_dependent_df['parts'].value_counts()}")
