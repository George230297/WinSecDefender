from abc import ABC, abstractmethod
from typing import Dict, Any

class IScanStrategy(ABC):
    @abstractmethod
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Executes the scan strategy on the given target.
        """
        pass
