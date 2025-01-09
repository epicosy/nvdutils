from pydantic import BaseModel


class BaseScores(BaseModel):
    value: float
    impact: float
    exploitability: float
