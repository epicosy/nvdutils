from pathlib import Path
from abc import ABC, abstractmethod

from nvdutils.data.collections.collection import CVECollection


class LoadStrategy(ABC):
    @abstractmethod
    def __call__(self, data_loader, data_path: Path, *args, **kwargs) -> CVECollection:
        # TODO: specify data_loader type and avoid circular imports
        """
        Organize data into a desired structure.
        """
        pass
