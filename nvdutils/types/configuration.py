from enum import Enum
from typing import List, Set
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
    part: CPEPart

    def equals(self, other):
        return self.name == other.name and self.vendor == other.vendor and self.part == other.part

    def __hash__(self):
        return hash((self.name, self.vendor, self.part))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.equals(other)

    def __str__(self):
        return f"{self.vendor} {self.name} {self.part.value}"


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
    version_start_including: str = None
    version_start_excluding: str = None
    version_end_including: str = None
    version_end_excluding: str = None

    def get_product(self) -> Product:
        return Product(name=self.cpe.product, vendor=self.cpe.vendor, part=CPEPart(self.cpe.part))


@dataclass
class Node:
    operator: str
    negate: bool
    cpe_match: List[CPEMatch]
    products: Set[Product] = field(default_factory=set)

    def get_products(self, part: CPEPart = None, is_vulnerable: bool = False):
        if not self.products:
            for cpe_match in self.cpe_match:
                if is_vulnerable and not cpe_match.vulnerable:
                    continue

                if part and cpe_match.cpe.part != CPEPart(part).value:
                    continue

                product = cpe_match.get_product()

                if str(product) in self.products:
                    continue

                self.products.add(product)

        return self.products

    def get_target_sw(self, skip_sw: list = None, is_vulnerable: bool = False):
        # Initialize target_sw as a defaultdict of sets to automatically handle duplicates
        target_sw = defaultdict(set)

        for cpe_match in self.cpe_match:
            key = f"{cpe_match.cpe.vendor} {cpe_match.cpe.product}"

            if skip_sw and cpe_match.cpe.target_sw in skip_sw:
                continue

            if is_vulnerable and not cpe_match.vulnerable:
                continue

            target_sw[key].add(cpe_match.cpe.target_sw)

        # Convert sets to lists for the final output
        return {key: list(value) for key, value in target_sw.items()}


@dataclass
class Configuration:
    nodes: List[Node]
    operator: str = None
    products: Set[Product] = field(default_factory=set)

    def get_products(self, part: CPEPart = None, is_vulnerable: bool = False):
        if not self.products:
            for node in self.nodes:
                self.products.update(node.get_products(part, is_vulnerable))

        return self.products

    def get_target_sw(self, skip_sw: list = None, is_vulnerable: bool = False):
        target_sw = defaultdict(list)

        for node in self.nodes:
            node_target_sw = node.get_target_sw(skip_sw, is_vulnerable)

            for key, value in node_target_sw.items():
                target_sw[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_sw = {key: list(set(value)) for key, value in target_sw.items()}

        return target_sw
