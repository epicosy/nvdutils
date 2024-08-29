from dataclasses import dataclass
from typing import Union, List, Dict


@dataclass
class Vendor:
    name: str
    aliases: List[str] = None
    products: Union[str, Dict[str, dict]] = None
    open_source: Dict[str, str] = None
    services: str = None
    advisories: str = None

    def is_vendor(self) -> bool:
        return self.products is not None

    def is_open_source(self, is_github: bool = False) -> bool:
        if self.open_source is None:
            return False
        if is_github:
            return 'github' in self.open_source
        return True


@dataclass
class CNA:
    id: str
    name: str
    root: str
    email: str
    scope: Dict[str, Vendor]

    def get_owners(self, lower: bool = False) -> List[str]:
        owners = []

        for vendor in self.scope.values():
            if vendor.is_open_source(is_github=True):
                owner_name_raw = vendor.open_source['github']
                owner_name = owner_name_raw.replace('-mirror', '')

                if lower:
                    owner_name = owner_name.lower()

                owners.append(owner_name)

        return owners

    def is_vendor(self):
        return any(vendor.is_vendor() for vendor in self.scope.values())

    def is_open_source(self, is_github: bool = False):
        return any(vendor.is_open_source(is_github=is_github) for vendor in self.scope.values())
