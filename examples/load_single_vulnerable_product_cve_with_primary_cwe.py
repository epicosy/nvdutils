from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, CWEOptions, CVSSOptions, DescriptionOptions, ConfigurationOptions

cve_options = CVEOptions(
    cwe_options=CWEOptions(has_cwe=True, in_secondary=False, is_single=True),
    cvss_options=CVSSOptions(),
    desc_options=DescriptionOptions(),
    config_options=ConfigurationOptions(is_single_vuln_product=True)
)

loader = JSONFeedsLoader(data_path='/home/epicosy/projects/phanes/data/nvd-json-data-feeds',
                         options=cve_options,
                         verbose=True)

data = loader.load()