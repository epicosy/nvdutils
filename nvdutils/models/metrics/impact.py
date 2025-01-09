from pydantic import BaseModel


class ImpactMetrics(BaseModel):
    confidentiality: str
    integrity: str
    availability: str

    def to_dict(self):
        return {
            'confidentiality': self.confidentiality,
            'integrity': self.integrity,
            'availability': self.availability
        }
