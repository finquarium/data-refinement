from typing import Optional
from pydantic import BaseModel

from refiner.models.offchain_schema import OffChainSchema

class Output(BaseModel):
    refinement_url: Optional[str] = None       # URL to the encrypted refined data (e.g., IPFS CID)
    output_schema: Optional[OffChainSchema] = None # The schema definition of the refined data