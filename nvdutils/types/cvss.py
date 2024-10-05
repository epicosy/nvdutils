from enum import Enum
from dataclasses import dataclass


class CVSSType(Enum):
    Primary = 1
    Secondary = 2


@dataclass
class ImpactMetrics:
    confidentiality: str
    integrity: str
    availability: str

    def to_dict(self):
        return {
            'confidentiality': self.confidentiality,
            'integrity': self.integrity,
            'availability': self.availability
        }


@dataclass
class CVSSScores:
    base: float
    impact: float
    exploitability: float


@dataclass
class BaseCVSS:
    source: str
    type: CVSSType
    version: str
    vector: str
    impact: ImpactMetrics
    scores: CVSSScores
    base_severity: str


@dataclass
class CVSSv2(BaseCVSS):
    access_vector: str
    access_complexity: str
    authentication: str
    ac_insuf_info: bool
    obtain_all_privilege: bool
    obtain_user_privilege: bool
    obtain_other_privilege: bool
    user_interaction_required: bool

    def to_dict(self):
        return {
            'source': self.source,
            'type': self.type.name,
            'version': self.version,
            'vector': self.vector,
            'confidentiality_impact': self.impact.confidentiality,
            'integrity_impact': self.impact.integrity,
            'availability_impact': self.impact.availability,
            'base_score': self.scores.base,
            'impact_score': self.scores.impact,
            'exploitability_score': self.scores.exploitability,
            'base_severity': self.base_severity,
            'access_vector': self.access_vector,
            'access_complexity': self.access_complexity,
            'authentication': self.authentication,
            'ac_insuf_info': self.ac_insuf_info,
            'obtain_all_privilege': self.obtain_all_privilege,
            'obtain_user_privilege': self.obtain_user_privilege,
            'obtain_other_privilege': self.obtain_other_privilege,
            'user_interaction_required': self.user_interaction_required
        }


@dataclass
class CVSSv3(BaseCVSS):
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str

    def to_dict(self):
        return {
            'source': self.source,
            'type': self.type.name,
            'version': self.version,
            'vector': self.vector,
            'confidentiality_impact': self.impact.confidentiality,
            'integrity_impact': self.impact.integrity,
            'availability_impact': self.impact.availability,
            'base_score': self.scores.base,
            'impact_score': self.scores.impact,
            'exploitability_score': self.scores.exploitability,
            'base_severity': self.base_severity,
            'attack_vector': self.attack_vector,
            'attack_complexity': self.attack_complexity,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'scope': self.scope
        }
