import json

from pathlib import Path
from tqdm import tqdm
from nvdutils.types.cna import CNA, Scope, Vendor


class CNABaseLoader:
    def __init__(self, path: str = '~/.nvdutils/cna-list/cnas', org_path: str = '~/.nvdutils/cna-list/organizations'):
        self.path = Path(path).expanduser()
        self.org_path = Path(org_path).expanduser()

        # check if the CNA data path exists
        if not self.path.exists():
            raise FileNotFoundError(f"{path} not found")

        # check if the organization data path exists
        if not self.org_path.exists():
            raise FileNotFoundError(f"{org_path} not found")

        self.records = {}
        self._vendors = {}

        for org_file in tqdm(self.org_path.iterdir(), desc="Loading organization data", unit='file'):
            with org_file.open('r') as f:
                org_json = json.load(f)
                vendor = Vendor(**org_json)
                self._vendors[vendor.id] = vendor

        for cna_file in tqdm(self.path.iterdir(), desc="Loading CNA data", unit='file'):
            with cna_file.open('r') as f:
                cna_json = json.load(f)
                scope = cna_json.pop('scope')
                organizations = scope.pop('organizations')
                scope['organizations'] = {org: self._vendors[org] for org in organizations}
                scope = Scope(**scope)
                cna = CNA(**cna_json, scope=scope)
                self.records[cna.email] = cna

    def __getitem__(self, key):
        return self.records[key]

    @property
    def vendors(self):
        return self._vendors
