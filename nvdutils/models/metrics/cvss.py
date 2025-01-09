from pydantic import BaseModel, Field, model_validator, field_validator
from nvdutils.common.enums.metrics import MetricsType, CVSSVersion
from nvdutils.models.metrics.impact import ImpactMetrics
from nvdutils.models.metrics.scores import BaseScores


class CVSS(BaseModel):
    source: str
    vector: str = Field(alias="vectorString")
    base_severity: str = Field(alias="baseSeverity")
    version: CVSSVersion
    metrics_type: MetricsType = Field(alias="type")
    impact_metrics: ImpactMetrics
    base_scores: BaseScores

    @field_validator("metrics_type", mode="before")
    def map_metrics_type(cls, value):
        if not value:
            raise ValueError("Missing metrics type")

        return MetricsType[value]

    @field_validator("version", mode="before")
    def map_version(cls, value):
        if not value:
            raise ValueError("Missing version")

        return CVSSVersion(int(float(value)))

    @model_validator(mode="before")
    def map_cvss_data(cls, values):
        cvss_data = values.get('cvssData')

        # Extract and organize the nested fields into base_scores and impact_metrics
        values['base_scores'] = {
            'value': cvss_data.get('baseScore'),
            'impact': values.get('impactScore'),
            'exploitability': values.get('exploitabilityScore')
        }

        values['impact_metrics'] = {
            'availability': cvss_data.get('availabilityImpact'),
            'confidentiality': cvss_data.get('confidentialityImpact'),
            'integrity': cvss_data.get('integrityImpact')
        }

        # Merge remaining cvss_data fields directly into values
        values.update(cvss_data)

        return values


class CVSSv2(CVSS):
    access_vector: str = Field(alias="accessVector")
    access_complexity: str = Field(alias="accessComplexity")
    authentication: str
    ac_insuf_info: bool = Field(alias="acInsufInfo", default=None)
    obtain_all_privilege: bool = Field(alias="obtainAllPrivilege", default=None)
    obtain_user_privilege: bool = Field(alias="obtainUserPrivilege", default=None)
    obtain_other_privilege: bool = Field(alias="obtainOtherPrivilege", default=None)
    user_interaction_required: bool = Field(alias="userInteractionRequired", default=None)

    def to_dict(self):
        return {
            'access_vector': self.access_vector,
            'access_complexity': self.access_complexity,
            'authentication': self.authentication,
            'ac_insuf_info': self.ac_insuf_info,
            'obtain_all_privilege': self.obtain_all_privilege,
            'obtain_user_privilege': self.obtain_user_privilege,
            'obtain_other_privilege': self.obtain_other_privilege,
            'user_interaction_required': self.user_interaction_required
        }


class CVSSv3(CVSS):
    attack_vector: str = Field(alias="attackVector")
    attack_complexity: str = Field(alias="attackComplexity")
    privileges_required: str = Field(alias="privilegesRequired")
    user_interaction: str = Field(alias="userInteraction")
    scope: str

    def to_dict(self):
        return {
            'attack_vector': self.attack_vector,
            'attack_complexity': self.attack_complexity,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'scope': self.scope
        }
