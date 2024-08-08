from dataclasses import dataclass


# TODO: Break down the statistics by CWE, CPE, etc.
@dataclass
class LoaderYearlyStats:
    """
        Class to store yearly statistics for the loader

        Attributes:
            year (int): The year of the statistics
            total (int): The total number of CVEs
            rejected (int): The number of rejected CVEs
            no_weaknesses (int): The number of CVEs with no weaknesses
            no_config_info (int): The number of CVEs with no configuration info
            no_vuln_products (int): The number of CVEs with no vulnerable products
            no_cwe_info (int): The number of CVEs with no CWE info
            no_cvss_v3 (int): The number of CVEs with no CVSS v3 metrics
            multiple_cwe (int): The number of CVEs with multiple CWEs
            multi_vuln (int): The number of CVEs with multiple vulnerabilities
            multi_component (int): The number of CVEs with multiple components
            cwe_other (int): The number of CVEs with other CWEs
            other (int): The number of other CVEs
    """
    year: int
    total: int = 0
    rejected: int = 0
    no_weaknesses: int = 0
    no_config_info: int = 0
    no_vuln_products: int = 0
    no_cwe_info: int = 0
    no_cvss_v3: int = 0
    multiple_cwe: int = 0
    multi_vuln: int = 0
    multi_component: int = 0
    cwe_other: int = 0
    other: int = 0

    def to_dict(self):
        return {
            'year': self.year,
            'total': self.total,
            'rejected': self.rejected,
            'no_weaknesses': self.no_weaknesses,
            'no_config_info': self.no_config_info,
            'no_vuln_products': self.no_vuln_products,
            'no_cwe_info': self.no_cwe_info,
            'no_cvss_v3': self.no_cvss_v3,
            'multiple_cwe': self.multiple_cwe,
            'multi_vuln': self.multi_vuln,
            'multi_component': self.multi_component,
            'cwe_other': self.cwe_other,
            'other': self.other
        }
