import json
import pandas as pd

from collections import defaultdict

from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, CWEOptions, CVSSOptions

loader_options = CVEOptions(
    cwe_options=CWEOptions(
        has_weaknesses=True
    ),
    cvss_options=CVSSOptions(
        has_v3=True
    )
)

root_cause_mapping_df = pd.read_csv('~/projects/phanes/vuln_mapping.csv')
root_cause_mapping = root_cause_mapping_df.set_index('cwe_id')['mapping'].to_dict()

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', verbose=True, options=loader_options)

# Populate the loader with CVE records
processed = 0
loaded = 0
skipped = 0

retained_ids = []

for year, records in loader.load(by_year=True, eager=False):
    print(f"Year: {year}, Records: {len(records)}")
    processed += loader.stats[year].total
    loaded += loader.stats[year].processed
    skipped += loader.stats[year].skipped

    for cve_id, cve in records.items():
        allowed_ids = defaultdict(list)

        for weakness in cve.get_weaknesses():
            for cwe_id_value in weakness.get_numeric_values():
                if cwe_id_value not in root_cause_mapping:
                    continue

                if root_cause_mapping[cwe_id_value] not in ['ALLOWED', 'ALLOWED-WITH-REVIEW']:
                    continue

                allowed_ids[weakness.type].append(cwe_id_value)

        if len(allowed_ids) == 0:
            skipped += 1
            loaded -= 1

            continue

        vuln_parts = cve.get_vulnerable_parts(values=True)

        # filter vulnerabilities that affect only hardware or are hardware specific
        if len(vuln_parts) == 1 and 'h' in vuln_parts:
            skipped += 1
            loaded -= 1

            continue

        retained_ids.append(cve_id)

print(f"Processed", processed)
print(f"Loaded", loaded)
print(f"Skipped", skipped)

# save target_ids to json file

with open('target_ids.json', 'w') as f:
    json.dump(retained_ids, f)
