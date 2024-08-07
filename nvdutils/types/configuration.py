from enum import Enum
from typing import List, Set, Dict
from dataclasses import dataclass, field
from collections import defaultdict


class CPEPart(Enum):
    Hardware = 'h'
    OS = 'o'
    Application = 'a'


@dataclass
class Product:
    name: str
    vendor: str
    vulnerable: bool
    part: CPEPart

    def equals(self, other):
        return (self.name == other.name and self.vendor == other.vendor and self.part == other.part
                and self.vulnerable == other.vulnerable)

    def __hash__(self):
        return hash((self.name, self.vendor, self.part, self.vulnerable))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.equals(other)

    def __str__(self):
        return f"{self.vendor} {self.name} {self.part.value} {self.vulnerable}"


@dataclass
class CPE:
    cpe_version: str
    part: str
    vendor: str
    product: str
    version: str = None
    update: str = None
    edition: str = None
    language: str = None
    sw_edition: str = None
    target_sw: str = None
    target_hw: str = None
    other: str = None


@dataclass
class CPEMatch:
    criteria_id: str
    criteria: str
    cpe: CPE
    vulnerable: bool
    is_runtime_environment: bool
    is_platform_specific_sw: bool
    is_platform_specific_hw: bool
    version_start_including: str = None
    version_start_excluding: str = None
    version_end_including: str = None
    version_end_excluding: str = None

    def get_product(self) -> Product:
        return Product(name=self.cpe.product, vendor=self.cpe.vendor, part=CPEPart(self.cpe.part),
                       vulnerable=self.vulnerable)


@dataclass
class Node:
    operator: str
    negate: bool
    cpe_match: List[CPEMatch]
    products: Set[Product] = field(default_factory=set)

    def get_products(self):
        if not self.products:
            for cpe_match in self.cpe_match:
                product = cpe_match.get_product()

                if str(product) in self.products:
                    continue

                self.products.add(product)

        return self.products

    def get_target(self, target_type: str, skip_targets: list = None, is_vulnerable: bool = False,
                   is_part: CPEPart = None, is_platform_specific: bool = False, strict: bool = False) \
            -> Dict[str, set]:
        """
        Get target values (software or hardware) for this node.
        :param target_type: Type of target to fetch ('sw' or 'hw')
        :param skip_targets: List of target values to skip
        :param is_vulnerable: Filter by vulnerability status
        :param is_part: Filter by CPE part
        :param is_platform_specific: Filter by platform-specific targets
        :param strict: Return target values only if CPE part is common across vulnerable matches, otherwise raises error
        :return: Dictionary of target values for this node
        """

        if target_type not in ['sw', 'hw']:
            raise ValueError("target_type must be either 'sw' or 'hw'")

        target_key = f'target_{target_type}'
        platform_specific_key = f'is_platform_specific_{target_type}'

        # Initialize target as a defaultdict of sets to automatically handle duplicates
        target_values = defaultdict(set)

        for cpe_match in self.cpe_match:
            if is_vulnerable and not cpe_match.vulnerable:
                continue

            if is_part and cpe_match.cpe.part != is_part.value:
                if strict:
                    raise ValueError(f"Part {is_part.value} is not common for all vulnerable matches")
                continue

            target_value = getattr(cpe_match.cpe, target_key)
            platform_specific_value = getattr(cpe_match, platform_specific_key)

            if skip_targets and target_value in skip_targets:
                continue

            if is_platform_specific and not platform_specific_value:
                continue

            key = f"{cpe_match.cpe.vendor} {cpe_match.cpe.product}"

            target_values[key].add(target_value)

        return target_values


@dataclass
class Configuration:
    nodes: List[Node]
    operator: str = None
    products: Set[Product] = field(default_factory=set)

    def is_platform_specific(self):
        return any(cpe_match.is_runtime_environment for node in self.nodes for cpe_match in node.cpe_match)

    def get_products(self):
        if not self.products:
            for node in self.nodes:
                self.products.update(node.get_products())

        return self.products

    def get_vulnerable_products(self):
        return {product for product in self.get_products() if product.vulnerable}

    def get_target(self, target_type: str, skip_sw: list = None, is_vulnerable: bool = False, is_part: CPEPart = None,
                   is_platform_specific: bool = False, strict: bool = False):
        """
            Get target software for this configuration.
            :param target_type: type of target to fetch ('sw' or 'hw')
            :param skip_sw: list of target software values to skip
            :param is_vulnerable: filter by vulnerability status
            :param is_part: filter by CPE part
            :param is_platform_specific: filter by platform-specific software
            :param strict: return target software values only if CPE part is common for all vulnerable matches,
            otherwise raises an error

            :return: dictionary of target software values for this configuration
        """
        target_values = defaultdict(list)

        for node in self.nodes:
            node_target_sw = node.get_target(target_type, skip_sw, is_vulnerable, is_part, is_platform_specific, strict)

            for key, value in node_target_sw.items():
                target_values[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_values = {key: list(set(value)) for key, value in target_values.items()}

        return target_values
