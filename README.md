# nvdutils

A comprehensive Python package for parsing, representing, filtering, and analyzing National Vulnerability Database (NVD) 
data. This library provides tools to work with CVE records, making it easier to process and extract insights from 
vulnerability data.

## Features

- **Flexible Data Loading**: Load CVE data from JSON files with support for different loading strategies
- **Rich Data Models**: Comprehensive Pydantic models for representing CVE data including descriptions, configurations, weaknesses, metrics, and references
- **Filtering Capabilities**: Filter CVEs based on various criteria using profiles
- **Data Collection**: Utilities for downloading NVD data feeds
- **Progress Tracking**: Built-in progress bars and statistics for data loading operations
- **Extensible Architecture**: Easily extend the library with custom loaders, profiles, and strategies

## Installation

```bash
pip install nvdutils
```

## Setup

Before using the package, you need to set up the data directory and download the NVD data:

```bash
# Create data directory
mkdir ~/.nvdutils
cd ~/.nvdutils

# Clone the NVD JSON data feeds repository
git clone https://github.com/fkie-cad/nvd-json-data-feeds.git
```

## Usage Examples

### Basic Usage: Loading All CVE Data

```python
from pathlib import Path
from nvdutils.loaders.json.default import JSONDefaultLoader

# Create a loader
loader = JSONDefaultLoader()

# Eagerly load all the data
cve_dictionary = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

# Access CVEs by ID
cve = cve_dictionary.get("CVE-2023-1234")
```

### Loading a Specific CVE by ID

```python
from pathlib import Path
from nvdutils.loaders.json.yearly import JSONYearlyLoader

# Create a loader
loader = JSONYearlyLoader()
data_path = Path("~/.nvdutils/nvd-json-data-feeds")

# Load a specific CVE by ID
cve = loader.load_by_id("CVE-2015-5334", data_path)

# Print the CVE details
print(cve)
```

### Filtering CVEs with Profiles

```python
from pathlib import Path
from nvdutils.loaders.json.default import JSONDefaultLoader
from nvdutils.data.profiles.zero_click import ZeroClickProfile

# Create a loader with a profile
loader = JSONDefaultLoader(profile=ZeroClickProfile, verbose=True)

# Load CVEs that match the profile
cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

print(f"Loaded {len(cve_dict)} CVEs")
```

### Creating Custom Profiles

```python
from dataclasses import dataclass, field
from nvdutils.data.profiles.base import BaseProfile
from nvdutils.data.criteria.weaknesses import CWECriteria, WeaknessesCriteria
from nvdutils.common.enums.weaknesses import WeaknessType

# Define criteria for CWE-787 weaknesses
cwe_787_criteria = WeaknessesCriteria(
    cwe_criteria=CWECriteria(
        cwe_id='CWE-787',
        is_single=True
    ),
    weakness_type=WeaknessType.Primary
)

# Create a custom profile
@dataclass
class CWE787Profile(BaseProfile):
    """Profile for selecting CVEs with CWE-787 as the primary weakness."""
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: cwe_787_criteria)
```

## Key Components

### Loaders

- **CVEDataLoader**: Base class for loading CVE data
- **JSONDefaultLoader**: Loader for JSON data with default strategy
- **JSONYearlyLoader**: Loader for JSON data organized by year

### Models

- **CVE**: Main model representing a CVE record
- **Descriptions**: Model for vulnerability descriptions
- **Configurations**: Model for affected configurations
- **Weaknesses**: Model for weakness types (CWEs)
- **Metrics**: Model for vulnerability metrics (CVSS)
- **References**: Model for external references

### Profiles and Criteria

- **BaseProfile**: Base class for filtering profiles
- **ZeroClickProfile**: Profile for zero-click vulnerabilities
- **Criteria Classes**: Various criteria for filtering CVEs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the LICENSE file.