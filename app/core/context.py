from typing import List, Dict, Any, Type
from .interfaces import IScanStrategy
from .strategies import NetworkScanStrategy, ServiceConfigStrategy, RegistryAuditStrategy, FileSystemStrategy
import logging

logger = logging.getLogger(__name__)

class ContextScanner:
    def __init__(self, target: str):
        self.target = target
        self.strategies: List[IScanStrategy] = []
        self.results: Dict[str, Any] = {}

    def add_strategy(self, strategy: IScanStrategy):
        self.strategies.append(strategy)

    def set_strategy(self, strategy: IScanStrategy):
        """Replaces all strategies with a single one"""
        self.strategies = [strategy]

    async def execute_scan(self) -> Dict[str, Any]:
        logger.info(f"Executing scan with {len(self.strategies)} strategies...")
        self.results = {}
        for strategy in self.strategies:
            try:
                result = await strategy.scan(self.target)
                self.results.update(result)
            except Exception as e:
                logger.error(f"Strategy {strategy.__class__.__name__} failed: {e}")
                self.results[strategy.__class__.__name__] = {"error": str(e)}
        
        return self.results
