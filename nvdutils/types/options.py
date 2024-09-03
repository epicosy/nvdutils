from datetime import datetime
from dataclasses import dataclass, field
from nvdutils.types.configuration import CPEPart
from typing import List

@dataclass
class CWEOptions:
    """
        Class to store options for filtering CWEs

        Attributes:
            has_cwe (bool): Whether to filter out CVEs with CWE IDs
            cwe_id (str): The CWE ID to filter out
            in_primary (bool): Whether to filter out CVEs with CWE IDs in the primary category
            in_secondary (bool): Whether to filter out CVEs with CWE IDs in the secondary category
    """
    has_cwe: bool = False
    cwe_id: str = None
    in_primary: bool = True
    in_secondary: bool = True
    is_single: bool = False


@dataclass
class CVSSOptions:
    """
        Class to store options for filtering CVSS metrics

        Attributes:
            has_v2 (bool): Whether to filter out CVEs with CVSS v2 metrics
            has_v3 (bool): Whether to filter out CVEs with CVSS v3 metrics
    """
    has_v2: bool = False
    has_v3: bool = False
    # TODO: Add more options


@dataclass
class ConfigurationOptions:
    """
        Class to store options for filtering configurations

        Attributes:
            has_config (bool): Whether to filter out CVEs without configurations
            has_vulnerable_products (bool): Whether to filter out CVEs without vulnerable products
            is_single_vuln_product (bool): Whether to filter out CVEs with multiple vulnerabilities
            is_single_config (bool): Whether to filter out CVEs with multiple configurations
            vuln_product_is_part (CPEPart): The vulnerable CPE is the specified part
    """
    has_config: bool = False
    has_vulnerable_products: bool = False
    is_single_vuln_product: bool = False
    is_single_config: bool = False
    vuln_product_is_part: CPEPart = None


@dataclass
class DescriptionOptions:
    """
        Class to store options for filtering descriptions

        Attributes:
            is_single_vuln (bool): Whether to filter out CVEs with multiple vulnerabilities
            is_single_component (bool): Whether to filter out CVEs with multiple components
    """
    is_single_vuln: bool = False
    is_single_component: bool = False


@dataclass
class CNAOptions:
    """
        Class to store options for filtering CNAs

        Attributes:
            emails list(str): Select CNAs by email
    """
    emails: List[str] = None


@dataclass
class CVEOptions:
    """
        Class to store options for filtering CVEs

        Attributes:
            start (int): The start year for the filter
            end (int): The end year for the filter
            cwe_options (CWEOptions): The options for filtering CWEs
            cvss_options (CVSSOptions): The options for filtering CVSS metrics
            config_options (ConfigurationOptions): The options for filtering configurations
            desc_options (DescriptionOptions): The options for filtering descriptions
    """
    start: int = 1999
    end: int = field(default_factory=lambda: datetime.now().year)
    cna_options: CNAOptions = field(default_factory=CNAOptions)
    cwe_options: CWEOptions = field(default_factory=CWEOptions)
    cvss_options: CVSSOptions = field(default_factory=CVSSOptions)
    config_options: ConfigurationOptions = field(default_factory=ConfigurationOptions)
    desc_options: DescriptionOptions = field(default_factory=DescriptionOptions)
