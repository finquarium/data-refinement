from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FinquariumUserUnrefined(BaseModel):
    id_hash: str

class FinquariumStatsUnrefined(BaseModel):
    total_volume: float
    transaction_count: int
    unique_assets: List[str]
    activity_period_days: int
    first_transaction_date: str # ISO datetime string
    last_transaction_date: str  # ISO datetime string

class FinquariumTransactionUnrefined(BaseModel):
    type: str
    asset: str
    quantity: float
    native_amount: float
    timestamp: str # ISO datetime string

class FinquariumDataUnrefined(BaseModel):
    user: FinquariumUserUnrefined
    stats: FinquariumStatsUnrefined
    transactions: List[FinquariumTransactionUnrefined] = Field(default_factory=list)

# Model for the survey-type data to help identify it
class SurveyMetadata(BaseModel):
    version: str
    timestamp: int
    basePoints: Optional[int] = None
    predictionPoints: Optional[int] = None

class SurveyDataUnrefined(BaseModel):
    metadata: SurveyMetadata
    expertise: Optional[Dict[str, Any]] = None
    strategy: Optional[Dict[str, Any]] = None
    psychology: Optional[Dict[str, Any]] = None
    contact: Optional[Dict[str, Any]] = None