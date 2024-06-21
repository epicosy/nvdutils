
from typing import List
from dataclasses import dataclass


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

    def get_vulnerable_products(self):
        if self.vuln_products:
            return self.vuln_products

        products = set()

        for cpe_match in self.cpe_match:
            if cpe_match.vulnerable:
                products.add(f"{cpe_match.cpe.vendor} {cpe_match.cpe.product}")

        self.vuln_products = list(products)

        return self.vuln_products


@dataclass
class Configuration:
    nodes: List[Node]
    operator: str = None
    vuln_products: List[str] = None

    def get_vulnerable_products(self):
        if self.vuln_products:
            return self.vuln_products

        products = set()

        for node in self.nodes:
            products.update(node.get_vulnerable_products())

        self.vuln_products = list(products)

        return self.vuln_products
