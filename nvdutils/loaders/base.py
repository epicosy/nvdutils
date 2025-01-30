import sys

from tqdm import tqdm
from pathlib import Path
from typing import List, Iterator

from nvdutils.models.cve import CVE
from nvdutils.data.stats.base import Stats
from nvdutils.data.profiles.base import BaseProfile
from nvdutils.data.collections.collection import CVECollection

from nvdutils.handlers.files.base import FileReader
from nvdutils.handlers.strategies.base import LoadStrategy
from nvdutils.handlers.strategies.default import DefaultStrategy


def get_files_from_path(path: Path, include_subdirectories: bool = False, pattern: str = "*") -> Iterator[Path] | None:
    """
        Collects files from the specified path.

        Args:
            path (Path): The root directory to search for files.
            include_subdirectories (bool): Whether to include files from subdirectories.
            pattern (str): The pattern to match files. Only applies when include_subdirectories is True.

        Returns:
            Iterator[Path]: A iterator with the files found in the specified path or None if the path does not exist.
    """

    expanded_path = path.expanduser()

    # Ensure the provided path exists
    if not expanded_path.exists():
        return None

    # Collect files based on whether subdirectories are included
    return expanded_path.rglob(pattern) if include_subdirectories else expanded_path.iterdir()


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

    # TODO: path and include_subdirectories should be moved to the __init__ method
    def load_by_id(self, cve_id: str, path: Path) -> CVE | None:
        """
            Looks up for the ID in the name of th files and returns the first match. The search is case-sensitive and
            the format of the ID should be CVE-YYYY-NNNN.

            Args:
                cve_id (str): The CVE ID to look up.
                path (Path): The path to search for the CVE ID.

            Returns:
                CVE: The CVE object if found, otherwise None.
        """
        # Check the format of the CVE ID
        parts = cve_id.split("-")

        if len(parts) != 3:
            return None

        _, year, number = parts
        cve_year_path = path / f"CVE-{year}"

        files = get_files_from_path(cve_year_path, True, pattern=f"*{cve_id}.*")

        if not files:
            files = get_files_from_path(path, True, pattern=f"*{cve_id}.*")

        if not files:
            return None

        for file_path in files:
            cve_object = self.load_from_file(file_path)

            if cve_object is not None:
                return cve_object

    def load_from_file(self, file_path: Path) -> CVE | None:
        """
            Loads a CVE object from a given file.

            Args:
                file_path (Path): The path to the file to load.

            Returns:
                CVE: The parsed CVE object if successful, otherwise None.
        """

        if not self.file_reader.is_file_valid(file_path):
            return None

        cve_data = self.file_reader(file_path)

        try:
            # TODO: provide parameter to skip validation errors
            return CVE(**cve_data)
        except Exception as e:
            print(e)
            print(f"Error parsing {file_path}")
            return None

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
        files = get_files_from_path(data_path, include_subdirectories)
        # TODO: provide format for validating the file name to be read, otherwise it can load any file in the directory
        progress_bar = tqdm(files, leave=False, desc="Loading CVE records")

        # Process each file
        for file_path in progress_bar:
            cve_object = self.load_from_file(file_path)

            if cve_object is None:
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
