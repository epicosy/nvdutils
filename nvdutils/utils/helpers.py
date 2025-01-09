import requests
from requests import Response

from nvdutils.types.references.reference import Reference


def get_url(reference: Reference, timeout: int = 5) -> Response | None:
    # TODO: decide if this should belong to the Reference class or not
    try:
        response = requests.get(reference.url, timeout=timeout)

        if response.status_code == 200:
            return response

    except requests.RequestException as e:
        print(f"Request to {reference.url} failed with exception: {e}")

    return None
