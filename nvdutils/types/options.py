from abc import abstractmethod
from datetime import datetime
from dataclasses import dataclass, field
from nvdutils.types.configuration import CPEPart
from typing import List

from nvdutils.types.cve import CVE

DEFAULT_START_YEAR = 1999
DEFAULT_END_YEAR = datetime.now().year


@dataclass
class OptionsCheck:
    @abstractmethod
    def __call__(self):
        """
            Check if the options are valid
        """
        return True

    def to_dict(self):
        return self.__dict__


@dataclass
class CWEOptionsCheck(OptionsCheck):
    no_cwe_info: bool = False
    no_weaknesses: bool = False

    def __call__(self):
        return not any([self.no_cwe_info, self.no_weaknesses])


@dataclass
class CWEOptions:
    """
        Class to store options for filtering CWEs

        Attributes:
            has_weaknesses (bool): Whether to filter out CVEs with no weaknesses
            has_cwe (bool): Whether to filter out CVEs with CWE IDs
            cwe_id (str): The CWE ID to filter out
            in_primary (bool): Whether to filter out CVEs with CWE IDs in the primary category
            in_secondary (bool): Whether to filter out CVEs with CWE IDs in the secondary category
    """
    has_weaknesses: bool = False
    has_cwe: bool = False
    cwe_id: str = None
    in_primary: bool = True
    in_secondary: bool = True
    is_single: bool = False

    def check(self, cve: CVE) -> CWEOptionsCheck:
        """
            Check the given CVE against the CWE options
        """

        return CWEOptionsCheck(
            no_weaknesses=self.has_weaknesses and not cve.has_weaknesses(),
            no_cwe_info=self.has_cwe and not cve.has_cwe(
                in_primary=self.in_primary,
                in_secondary=self.in_secondary,
                is_single=self.is_single,
                cwe_id=self.cwe_id
            )
        )


@dataclass
class CVSSOptionsCheck(OptionsCheck):
    no_cvss_v3: bool
    v3_attack_vector: bool
    v3_attack_comp: bool
    v3_priv_req: bool
    v3_user_inter: bool
    v3_scope: bool
    v3_conf_impact: bool
    v3_int_impact: bool
    v3_avail_impact: bool

    def __call__(self):
        return not any([self.no_cvss_v3,
                        self.v3_attack_vector,
                        self.v3_attack_comp,
                        self.v3_priv_req,
                        self.v3_user_inter,
                        self.v3_scope,
                        self.v3_conf_impact,
                        self.v3_int_impact,
                        self.v3_avail_impact])


@dataclass
class CVSSOptions:
    """
        Class to store options for filtering CVSS metrics

        Attributes:
            has_v2 (bool): Whether to filter out CVEs with CVSS v2 metrics
            has_v3 (bool): Whether to filter out CVEs with CVSS v3 metrics
            v3_attack_vector (str): The attack vector to include
    """
    has_v2: bool = False
    has_v3: bool = False
    v3_attack_vector: str = None
    v3_priv_req: str = None
    v3_user_inter: str = None
    v3_attack_comp: str = None
    v3_scope: str = None
    v3_conf_impact: str = None
    v3_int_impact: str = None
    v3_avail_impact: str = None

    # TODO: Add more options

    def check(self, cve: CVE):
        cvss_v3 = cve.get_cvss_v3()

        return CVSSOptionsCheck(
            no_cvss_v3=not cve.has_cvss_v3() if self.has_v3 else False,
            v3_attack_vector=self.v3_attack_vector and cvss_v3.get('attack_vector', None) != self.v3_attack_vector,
            v3_attack_comp=self.v3_attack_comp and cvss_v3.get('attack_complexity', None) != self.v3_attack_comp,
            v3_priv_req=self.v3_priv_req and cvss_v3.get('privileges_required', None) != self.v3_priv_req,
            v3_user_inter=self.v3_user_inter and cvss_v3.get('user_interaction', None) != self.v3_user_inter,
            v3_scope=self.v3_scope and cvss_v3.get('scope', None) != self.v3_scope,
            v3_conf_impact=self.v3_conf_impact and cvss_v3.get('confidentiality_impact', None) != self.v3_conf_impact,
            v3_int_impact=self.v3_int_impact and cvss_v3.get('integrity_impact', None) != self.v3_int_impact,
            v3_avail_impact=self.v3_avail_impact and cvss_v3.get('availability_impact', None) != self.v3_avail_impact
        )


@dataclass
class ConfigurationOptionsCheck(OptionsCheck):
    no_config_info: bool
    no_vuln_products: bool
    multi_vuln_products: bool

    def __call__(self):
        return not any([self.no_config_info, self.no_vuln_products, self.multi_vuln_products])


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

    def check(self, cve: CVE) -> ConfigurationOptionsCheck:
        return ConfigurationOptionsCheck(
            no_config_info=self.has_config and len(cve.configurations) == 0,
            no_vuln_products=self.has_vulnerable_products and not cve.get_vulnerable_products(),
            multi_vuln_products=self.is_single_vuln_product and not cve.is_single_vuln_product(self.vuln_product_is_part)
        )
        # check.multi_configs = self.is_single_config and not cve.is_single_config()


@dataclass
class DescriptionOptionsCheck(OptionsCheck):
    multi_vuln: bool
    multi_component: bool

    def __call__(self):
        return not any([self.multi_vuln, self.multi_component])


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

    def check(self, cve: CVE) -> DescriptionOptionsCheck:
        return DescriptionOptionsCheck(
            multi_vuln=self.is_single_vuln and cve.has_multiple_vulnerabilities(),
            multi_component=self.is_single_component and cve.has_multiple_components()
        )


@dataclass
class CVEOptionsCheck(OptionsCheck):
    is_rejected: bool
    not_in_sources: bool
    cwe_options_check: CWEOptionsCheck
    cvss_options_check: CVSSOptionsCheck
    config_options_check: ConfigurationOptionsCheck
    desc_options_check: DescriptionOptionsCheck

    def __call__(self):
        return not any([
            self.not_in_sources,
            self.is_rejected,
            not self.cwe_options_check(),
            not self.cvss_options_check(),
            not self.config_options_check(),
            not self.desc_options_check()
        ])

    def to_dict(self):
        return {
            'is_rejected': self.is_rejected,
            'not_in_sources': self.not_in_sources,
            'cwe_options_check': self.cwe_options_check.to_dict(),
            'cvss_options_check': self.cvss_options_check.to_dict(),
            'config_options_check': self.config_options_check.to_dict(),
            'desc_options_check': self.desc_options_check.to_dict()
        }


@dataclass
class CVEOptions:
    """
        Class to store options for filtering CVEs

        Attributes:
            start (int): The start year for the filter
            end (int): The end year for the filter
            source_identifiers (List[str]): The source identifiers to include
            cwe_options (CWEOptions): The options for filtering CWEs
            cvss_options (CVSSOptions): The options for filtering CVSS metrics
            config_options (ConfigurationOptions): The options for filtering configurations
            desc_options (DescriptionOptions): The options for filtering descriptions
    """
    start: int = DEFAULT_START_YEAR
    end: int = DEFAULT_END_YEAR
    source_identifiers: List[str] = field(default_factory=list)
    cwe_options: CWEOptions = field(default_factory=CWEOptions)
    cvss_options: CVSSOptions = field(default_factory=CVSSOptions)
    config_options: ConfigurationOptions = field(default_factory=ConfigurationOptions)
    desc_options: DescriptionOptions = field(default_factory=DescriptionOptions)

    # TODO: Should distinguish between passing the checks (to be done) and the actual filtering (done)
    def check(self, cve: CVE) -> CVEOptionsCheck:
        return CVEOptionsCheck(
            is_rejected=not cve.is_valid(),
            not_in_sources=len(self.source_identifiers) > 0 and cve.source not in self.source_identifiers,
            cwe_options_check=self.cwe_options.check(cve),
            cvss_options_check=self.cvss_options.check(cve),
            config_options_check=self.config_options.check(cve),
            desc_options_check=self.desc_options.check(cve)
        )
