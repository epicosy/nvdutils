import json
from pathlib import Path
from dataclasses import dataclass, field

from cpelib.types.definitions import CPEPart
from nvdutils.common.enums.weaknesses import WeaknessType
from nvdutils.loaders.json.default import JSONDefaultLoader
from nvdutils.data.profiles.zero_click import ZeroClickProfile
from nvdutils.data.criteria.descriptions import DescriptionsCriteria
from nvdutils.data.criteria.weaknesses import CWECriteria, WeaknessesCriteria
from nvdutils.data.criteria.configurations import AffectedProductCriteria, ConfigurationsCriteria


single_primary_cwe_787_weakness_criteria = WeaknessesCriteria(
    cwe_criteria=CWECriteria(
        cwe_id='CWE-787',
        is_single=True
    ),
    weakness_type=WeaknessType.Primary
)

single_app_config_criteria = ConfigurationsCriteria(
    affected_products=AffectedProductCriteria(
        part=CPEPart.Application,
        is_single=True
    )
)
single_sentence_description_criteria = DescriptionsCriteria(is_single_sentence=True)


@dataclass
class CWE787RemoteZeroClickInAppsProfile(ZeroClickProfile):
    """
        Profile for selecting CVEs that affect only a product that is an application.
    """
    configuration_criteria: ConfigurationsCriteria = field(default_factory=lambda: single_app_config_criteria)
    weakness_criteria: WeaknessesCriteria = field(default_factory=lambda: single_primary_cwe_787_weakness_criteria)
    description_criteria: DescriptionsCriteria = field(default_factory=lambda: single_sentence_description_criteria)


loader = JSONDefaultLoader(verbose=True, profile=CWE787RemoteZeroClickInAppsProfile)
cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)

print(f"Loaded {len(cve_dict)} CVEs")

with open("single_sentence_cwe_787_remote_zero_click_in_single_app_cves.json", "w") as f:
    json.dump(list(cve_dict.entries.keys()), f, indent=4)
