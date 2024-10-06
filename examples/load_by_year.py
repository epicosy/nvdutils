from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=CVEOptions(start=2000, end=2008),
                         verbose=True)

# Populate the loader with CVE records
loader.load(by_year=True)

for year, records in loader.records.items():
    print(f"Year: {year}, Records: {len(records)}")
