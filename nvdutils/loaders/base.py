import sys

from tqdm import tqdm
from typing import List
from pathlib import Path

from nvdutils.models.cve import CVE
from nvdutils.data.stats.base import Stats
from nvdutils.data.profiles.base import BaseProfile
from nvdutils.data.collections.collection import CVECollection

from nvdutils.handlers.files.base import FileReader
from nvdutils.handlers.strategies.base import LoadStrategy
from nvdutils.handlers.strategies.default import DefaultStrategy


class CVEDataLoader:
    def __init__(self, file_reader: FileReader, load_strategy: LoadStrategy = None, profile: BaseProfile = None,
                 verbose: bool = False):
        self.verbose = verbose
        self.profile = profile
        self.file_reader = file_reader
        self.load_strategy = load_strategy
        self.stats = Stats()  # TODO: should be configurable

        if profile is None:
            self.profile = BaseProfile

        if load_strategy is None:
            self.load_strategy = DefaultStrategy()

    def __call__(self, data_path: Path, include_subdirectories: bool = False, *args, **kwargs) -> List[CVE]:
        """
        Lazily load CVE records from the specified path.

        Args:
            data_path (Path): The root directory or file to load data from.
            include_subdirectories (bool): Whether to include files from subdirectories.
            *args: Additional arguments for file reading.
            **kwargs: Additional keyword arguments for file reading.

        Yields:
            CVE: Parsed CVE objects.

        Raises:
            FileNotFoundError: If the provided data path does not exist.
        """
        expanded_data_path = data_path.expanduser()

        # Ensure the provided path exists
        if not expanded_data_path.exists():
            raise FileNotFoundError(f"{expanded_data_path} not found")

        # Collect files based on whether subdirectories are included
        files = expanded_data_path.rglob("*") if include_subdirectories else expanded_data_path.iterdir()
        # TODO: provide format for validating the file name to be read, otherwise it can load any file in the directory
        progress_bar = tqdm(files, leave=False, desc="Loading CVE records")

        # Process each file
        for file_path in progress_bar:
            if not self.file_reader.is_file_valid(file_path):
                continue

            cve_data = self.file_reader(file_path)

            try:
                # TODO: provide parameter to skip validation errors
                cve_object = CVE(**cve_data)
            except Exception as e:
                print(e)
                print(f"Error parsing {file_path}")
                continue

            profile = self.profile()
            outcome = profile(cve_object)
            self.stats.update(outcome, profile)
            progress_bar.set_postfix(Selected=self.stats.selected, Skipped=self.stats.skipped)

            if self.verbose:
                # progress_bar.set_description()
                sys.stdout.write("\033[1F")  # Move cursor up one line
                sys.stdout.write("\033[K")  # Clear the line
                tqdm.write(self.stats.display())  # Write the new log

            if outcome:
                yield cve_object

    def load(self, data_path: Path, **kwargs) -> CVECollection:
        """
        Eagerly loads CVE records with a strategy into a dictionary.

        Args:
            data_path (Path): The root directory or file to load data from.
            **kwargs: Additional arguments passed to the lazy loading method (__call__).

        Returns:
            CVECollection: A dictionary containing all loaded CVE records.
        """

        return self.load_strategy(self, data_path, **kwargs)
