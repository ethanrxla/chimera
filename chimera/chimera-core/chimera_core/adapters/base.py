from abc import ABC, abstractmethod
from typing import Any, List


class AdapterBase(ABC):
    id: str
    capabilities: List[str]

    @abstractmethod
    def run(self, targets: List[str], *args: Any, **kwargs: Any) -> dict:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, *args: Any, **kwargs: Any):
        raise NotImplementedError
