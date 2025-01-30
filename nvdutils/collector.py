import shutil
import requests
import functools

from tqdm import tqdm
from pathlib import Path
from requests import Response
from typing import Union, Tuple
from urllib.parse import urlparse


# TODO: integrate into a dedicated class for collecting the NVD data feeds
def download_file_from_url(working_dir: Path, url: str, extract: bool = False) -> Union[Tuple[Response, Path], None]:
    # TODO: if the file exists and is not empty, then skip the download
    if 'http' not in url:
        print(f"URL {url} is not valid.")
        return None

    file_path = working_dir / Path(urlparse(url).path).name
    extract_file_path = working_dir / file_path.stem
    response = requests.get(url, stream=True, allow_redirects=True)

    if response.status_code != 200:
        print(f"Request to {url} returned status code {response.status_code}")
        return None

    total_size_in_bytes = int(response.headers.get('Content-Length', 0))

    if file_path.exists() and file_path.stat().st_size == total_size_in_bytes:
        print(f"File {file_path} exists. Skipping download...")
    else:
        desc = "(Unknown total file size)" if total_size_in_bytes == 0 else ""
        response.raw.read = functools.partial(response.raw.read, decode_content=True)  # Decompress if needed

        with tqdm.wrapattr(response.raw, "read", total=total_size_in_bytes, desc=desc) as r_raw:
            with file_path.open("wb") as f:
                shutil.copyfileobj(r_raw, f)

    if extract:
        if not extract_file_path.exists():
            print(f"Extracting file {extract_file_path}...")
            shutil.unpack_archive(file_path, working_dir)

        return response, extract_file_path

    return response, file_path
