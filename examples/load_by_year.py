from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, CWEOptions

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', verbose=True,
                         options=CVEOptions(start=2000, end=2001, cwe_options=CWEOptions(has_weaknesses=True)))

# Populate the loader with CVE records

for year, records in loader.load(by_year=True, eager=False):
    print(f"Year: {year}, Records: {len(records)}")
