from enum import Enum
from typing import List
from dataclasses import dataclass
from collections import defaultdict


class CPEPart(Enum):
    Hardware = 'h'
    OS = 'o'
    Application = 'a'


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


@dataclass
class Node:
    operator: str
    negate: bool
    cpe_match: List[CPEMatch]
    vuln_products: List[str] = None

    def get_vulnerable_products(self, part: CPEPart = None):
        if self.vuln_products:
            return self.vuln_products

        products = set()

        for cpe_match in self.cpe_match:
            if cpe_match.vulnerable:
                if part and cpe_match.cpe.part != CPEPart(part).value:
                    continue

                products.add(f"{cpe_match.cpe.vendor} {cpe_match.cpe.product}")

        self.vuln_products = list(products)

        return self.vuln_products

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
    vuln_products: List[str] = None

    def get_vulnerable_products(self, part: CPEPart = None):
        if self.vuln_products:
            return self.vuln_products

        products = set()

        for node in self.nodes:
            products.update(node.get_vulnerable_products(part))

        self.vuln_products = list(products)

        return self.vuln_products

    def get_target_sw(self, skip_sw: list = None, is_vulnerable: bool = False):
        target_sw = defaultdict(list)

        for node in self.nodes:
            node_target_sw = node.get_target_sw(skip_sw, is_vulnerable)

            for key, value in node_target_sw.items():
                target_sw[key].extend(value)

        # Convert lists to sets to remove duplicates, then back to lists
        target_sw = {key: list(set(value)) for key, value in target_sw.items()}

        return target_sw
