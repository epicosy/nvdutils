import re
import requests

from dataclasses import dataclass, field
from typing import List, Dict
from urllib.parse import urlparse

from nvdutils.types.cvss import BaseCVSS
from nvdutils.types.weakness import Weakness, WeaknessType
from nvdutils.types.configuration import Configuration, CPEPart
from nvdutils.utils.templates import (MULTI_VULNERABILITY, MULTI_COMPONENT, ENUMERATIONS, FILE_NAMES_PATHS,
                                      VARIABLE_NAMES, URL_PARAMETERS)


multiple_vulnerabilities_pattern = re.compile(MULTI_VULNERABILITY, re.IGNORECASE)
multiple_components_pattern = re.compile(MULTI_COMPONENT, re.IGNORECASE)
enumerations_pattern = re.compile(ENUMERATIONS, re.IGNORECASE)
file_names_paths_pattern = re.compile(FILE_NAMES_PATHS, re.IGNORECASE)
variable_names_pattern = re.compile(VARIABLE_NAMES, re.IGNORECASE)
url_parameters_pattern = re.compile(URL_PARAMETERS, re.IGNORECASE)


@dataclass
class Description:
    lang: str
    value: str

    def is_disputed(self):
        return '** DISPUTED' in self.value

    def is_unsupported(self):
        return '** UNSUPPORTED' in self.value

    def has_multiple_vulnerabilities(self):
        match = multiple_vulnerabilities_pattern.search(self.value)

        return match and len(match.group('vuln_type').split()) < 5

    def has_multiple_components(self):
        match = multiple_components_pattern.search(self.value)

        if match and len(match.group(2).split()) < 5:
            return True

        # check for enumerations
        if re.findall(enumerations_pattern, self.value):
            return True

        # check for multiple distinct file names/paths, variable names, and url parameters
        for pattern in [file_names_paths_pattern, variable_names_pattern, url_parameters_pattern]:
            match = re.findall(pattern, self.value)

            if match:
                # check if the matches are unique and greater than 2 (margin for misspellings and other issues)
                return len(set(match)) > 2

        # TODO: probably there are more, but this is a good start

        return False

    def __str__(self):
        return f"{self.lang}: {self.value}"


@dataclass
class Reference:
    url: str
    source: str
    tags: List[str] = field(default_factory=list)
    status: int = None
    content: str = None
    domain: str = None

    def __str__(self):
        return f"{self.source}: {self.url} ({', '.join(self.tags)})"

    def get_domain(self):
        if self.domain:
            return self.domain

        self.domain = urlparse(self.url).netloc

        return self.domain

    def get(self):
        try:
            response = requests.get(self.url, timeout=5)
            self.status = response.status_code

            if self.status == 200:
                self.content = response.text

                return True

        except requests.RequestException as e:
            print(f"Request to {self.url} failed with exception: {e}")
            self.status = -1

        return False


@dataclass
class CVE:
    id: int
    status: str
    descriptions: List[Description]
    configurations: List[Configuration]
    weaknesses: Dict[str, Weakness]
    metrics: Dict[str, BaseCVSS]
    references: List[Reference]
    vuln_products: List[str] = None
    domains: List[str] = None

    def get_tags(self):
        tags = set()

        for ref in self.references:
            tags.update(ref.tags)

        return list(tags)

    def get_domains(self):
        if self.domains:
            return self.domains

        domains = set()

        for ref in self.references:
            domains.add(ref.get_domain())

        return list(domains)

    def has_status(self):
        return self.status is not None

    def has_weaknesses(self):
        return len(self.weaknesses) > 0

    def has_cwe(self, in_primary: bool = False, in_secondary: bool = False, is_single: bool = False,
                cwe_id: str = None) -> bool:
        if not self.has_weaknesses():
            return False

        primary = None
        secondary = None

        if in_primary:
            primary = self.weaknesses[WeaknessType.Primary.name]

        if in_secondary:
            secondary = self.weaknesses[WeaknessType.Secondary.name]

        if is_single:
            if primary and not primary.is_single():
                return False
            if secondary and not secondary.is_single():
                return False

        if primary and not primary.is_cwe_id(cwe_id):
            return False

        if secondary and not secondary.is_cwe_id(cwe_id):
            return False

        return True

    def has_cvss_v3(self):
        return any(['cvssMetricV3' in k for k in self.metrics.keys()])

    def get_vulnerable_products(self, part: CPEPart = None):
        if self.vuln_products:
            return self.vuln_products

        products = set()

        for configuration in self.configurations:
            products.update(configuration.get_vulnerable_products(part))

        self.vuln_products = list(products)

        return self.vuln_products

    def is_single_vuln_product(self, part: CPEPart = None):
        return len(self.get_vulnerable_products(part)) == 1

    def is_valid(self):
        if not self.status:
            return False

        if self.is_disputed():
            return False

        if self.is_unsupported():
            return False

        return self.status in ['Modified', 'Analyzed']

    def get_eng_description(self) -> Description:
        for desc in self.descriptions:
            if desc.lang == 'en':
                return desc

        raise ValueError('No english description')

    def has_multiple_vulnerabilities(self):
        desc = self.get_eng_description()
        return desc.has_multiple_vulnerabilities()

    def has_multiple_components(self):
        desc = self.get_eng_description()
        return desc.has_multiple_components()

    def is_disputed(self):
        desc = self.get_eng_description()

        return desc.is_disputed()

    def is_unsupported(self):
        desc = self.get_eng_description()

        return desc.is_unsupported()

    def __str__(self):
        return (f"CVE-{self.id}:"
                "\n\tDescriptions:\n\t" + '\n\t\t'.join(str(desc) for desc in self.descriptions) +
                "\n\tReferences:\n\t" + '\n\t\t'.join(str(ref) for ref in self.references))
