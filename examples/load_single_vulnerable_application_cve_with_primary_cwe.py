from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, CWEOptions, ConfigurationOptions
from nvdutils.types.configuration import CPEPart

cve_options = CVEOptions(
    cwe_options=CWEOptions(has_cwe=True, in_secondary=False, is_single=True),
    config_options=ConfigurationOptions(is_single_vuln_product=True, vuln_product_is_part=CPEPart.Application)
)

loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds',
                         options=cve_options,
                         verbose=True)

loader.load()
print(len(loader))
