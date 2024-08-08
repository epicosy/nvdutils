import re
import requests

from typing import List, Dict, Set, Union, Tuple
from urllib.parse import urlparse
from collections import defaultdict
from dataclasses import dataclass, field


from nvdutils.types.cvss import BaseCVSS
from nvdutils.types.weakness import Weakness, WeaknessType
from nvdutils.types.configuration import Configuration, CPEPart, Product
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
    source: str
    status: str
    descriptions: List[Description]
    configurations: List[Configuration]
    weaknesses: Dict[str, Weakness]
    metrics: Dict[str, BaseCVSS]
    references: List[Reference]
    products: Set[Product] = field(default_factory=set)
    domains: List[str] = None

    def is_platform_specific(self, part: CPEPart = None) -> Tuple[bool, bool, bool]:
        """
            Check if the CVE is platform-specific
            :param part: if specified, check if the CVE is platform-specific for the specified part

            :return: tuple of booleans indicating if the CVE is platform-specific by runtime, target software, and
            target hardware
        """

        platform_specific_config_counter = 0
        not_platform_specific_config_counter = 0
        is_platform_specific_by_tgt_sw = None
        is_platform_specific_by_tgt_hw = None

        tgt_sw_values = defaultdict(set)
        tgt_hw_values = defaultdict(set)

        for configuration in self.configurations:
            vuln_products = configuration.get_vulnerable_products()

            if len(vuln_products) == 0:
                continue

            if configuration.is_platform_specific():
                platform_specific_config_counter += 1
            else:
                not_platform_specific_config_counter += 1

            if is_platform_specific_by_tgt_sw is not False:
                try:
                    config_target_sw = configuration.get_target(target_type='sw', skip_sw=['*', '-'], strict=True,
                                                                is_vulnerable=True, is_part=part, abstract=True,
                                                                is_platform_specific=True)
                    for vendor_product, target_sw in config_target_sw.items():
                        for sw in target_sw:
                            tgt_sw_values[vendor_product].add(sw)

                except ValueError:
                    is_platform_specific_by_tgt_sw = False
                    tgt_sw_values = defaultdict(set)

            if is_platform_specific_by_tgt_hw is not False:
                try:
                    config_target_hw = configuration.get_target(target_type='hw', skip_sw=['*', '-'], strict=True,
                                                                is_vulnerable=True, is_part=part, abstract=True,
                                                                is_platform_specific=True)
                    for vendor_product, target_hw in config_target_hw.items():
                        for hw in target_hw:
                            tgt_hw_values[vendor_product].add(hw)

                except ValueError:
                    is_platform_specific_by_tgt_hw = False
                    tgt_hw_values = defaultdict(set)

        is_platform_specific_by_runtime = platform_specific_config_counter > not_platform_specific_config_counter
        # is platform specific when at least one of the vulnerable products is OS/Device-specific
        is_platform_specific_by_tgt_sw = any([len(_v) == 1 for _v in tgt_sw_values.values()])
        # is platform specific when at least one of the vulnerable products is Arch/Device-specific
        is_platform_specific_by_tgt_hw = any([len(_v) == 1 for _v in tgt_hw_values.values()])

        return is_platform_specific_by_runtime, is_platform_specific_by_tgt_sw, is_platform_specific_by_tgt_hw

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

    def get_products(self):
        """
            Get all products for this CVE
        """
        if not self.products:
            for configuration in self.configurations:
                self.products.update(configuration.get_products())

        return self.products

    def get_vulnerable_products(self, part: CPEPart = None):
        """
            Get all vulnerable products for this CVE
            :param part: includes only the vulnerable products of the specified part
        """

        if part:
            return {product for product in self.get_products() if product.vulnerable and product.part == part}

        return {product for product in self.get_products() if product.vulnerable}

    def get_vulnerable_parts(self, ordered: bool = False, values: bool = False, string: bool = False) \
            -> Union[Set[CPEPart], Set[str], List[str], str]:

        if values:
            _output = {product.part.value for product in self.get_vulnerable_products()}

            if ordered:
                _output = sorted(_output)

            if string:
                _output = "::".join(_output)

        else:
            _output = {product.part for product in self.get_vulnerable_products()}

        return _output

    def is_single_vuln_product(self, part: CPEPart = None):
        """
            Check if the CVE is vulnerable in a single product
            :param part: if specified, check if the CVE is vulnerable in a single product of the specified part and
                        no other products
        """
        vulnerable_products = self.get_vulnerable_products()

        if part:
            return (len(vulnerable_products) == 1 and
                    all(product.part == part for product in vulnerable_products))

        return len(vulnerable_products) == 1

    def get_target(self, target_type: str, skip_sw: list = None, is_vulnerable: bool = False, is_part: CPEPart = None,
                   is_platform_specific: bool = False, strict: bool = False) -> Dict[str, list]:
        """
            Get target software for this CVE
            :param target_type: type of target software to fetch ('sw' or 'hw')
            :param skip_sw: list of target software values to skip
            :param is_vulnerable: filter by vulnerability status
            :param is_part: filter by CPE part
            :param is_platform_specific: filter by platform-specific software
            :param strict: return target software values only if CPE part is common for all vulnerable matches,
            otherwise raises an error

            :return: dictionary of target software values for this CVE
        """
        assert isinstance(is_part, CPEPart), 'is_part must be an instance of CPEPart'

        target_values = defaultdict(list)

        for configuration in self.configurations:
            config_target_sw = configuration.get_target(target_type, skip_sw, is_vulnerable, is_part,
                                                        is_platform_specific, strict)

            for key, value in config_target_sw.items():
                target_values[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_values = {key: list(set(value)) for key, value in target_values.items()}

        return target_values

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
