from typing import Dict
from pathlib import Path
from abc import ABC, abstractmethod


class FileReader(ABC):
    def __init__(self, extension: str, **kwargs):
        self.extension = extension

    def is_file_valid(self, path: Path) -> bool:
        if path.is_file():
            if path.suffix == self.extension:
                if path.stat().st_size != 0:
                    # skip empty files
                    return True

        return False

    @abstractmethod
    def __call__(self, path: Path) -> Dict:
        raise NotImplementedError
