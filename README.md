# nvdutils
A package for parsing, representing, and filtering NVD data.

### Setup 
```sh
$ mkdir ~/.nvdutils
$ cd ~/.nvdutils
# Data for the JSONFeedsLoader
$ git clone https://github.com/fkie-cad/nvd-json-data-feeds.git
# CNA list for the base CVEDataLoader
$ git clone https://github.com/epicosy/cna-list.git
```

### Usage

```python
    from nvdutils.core.loaders.json_loader import JSONFeedsLoader
    from nvdutils.types.options import CVEOptions

    cve_options = CVEOptions()
    cve_options.cwe_options.cwe_id = 'CWE-79'
    cve_options.cwe_options.has_cwe = True
    cve_options.cwe_options.in_secondary = False
    cve_options.cwe_options.is_single = True
    cve_options.cvss_options.has_v3 = True
    cve_options.config_options.is_single_vuln_product = True
    cve_options.desc_options.is_single_component = True
    cve_options.desc_options.is_single_vuln = True

    # https://github.com/fkie-cad/nvd-json-data-feeds
    loader = JSONFeedsLoader(data_path='/path/to/nvd-json-data-feeds', options=cve_options,
                             verbose=True)
    loader.load()
    print(len(loader))

    cve = JSONFeedsLoader.load_cve('/path/to/CVE-2019-0001.json')
    print(cve)
```
