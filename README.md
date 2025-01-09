# nvdutils
A package for parsing, representing, and filtering NVD data.

### Setup 
```sh
$ mkdir ~/.nvdutils
$ cd ~/.nvdutils
# Data for the JSONFeedsLoader
$ git clone https://github.com/fkie-cad/nvd-json-data-feeds.git
```

### Usage

```python
from pathlib import Path
from nvdutils.loaders.json.default import JSONDefaultLoader

loader = JSONDefaultLoader()
# Eagerly load all the data
cve_dictionary = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

```
