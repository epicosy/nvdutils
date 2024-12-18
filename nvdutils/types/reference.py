import requests

from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List


@dataclass
class Reference:
    url: str
    source: str
    tags: List[str] = field(default_factory=list)
    status: int = None
    content: str = None
    domain: str = None
    processed_url: str = None  # URL after preprocessing

    def has_patch_tag(self):
        return "Patch" in self.tags

    def to_dict(self):
        return {
            "url": self.url,
            "source": self.source,
            "tags": self.tags,
            "status": self.status,
            "content": self.content,
            "domain": self.domain,
            "processed_url": self.processed_url
        }

    def __str__(self):
        return f"{self.source}: {self.url} ({', '.join(self.tags)})"

    def get_domain(self):
        if self.domain:
            return self.domain

        self.domain = urlparse(self.url).netloc

        return self.domain

    def get_path(self):
        return urlparse(self.url).path

    def get(self):
        try:
            response = requests.get(self.url, timeout=5)
            self.status = response.status_code

            if self.status == 200:
                self.content = response.text

                return True

        except requests.RequestException as e:
            print(f"Request to {self.url} failed with exception: {e}")
            self.status = -1

        return False


@dataclass
class CommitReference(Reference):
    vcs: str = None
    owner: str = None
    repo: str = None
    sha: str = None

    @classmethod
    def from_reference(cls, reference: Reference, vcs: str, owner: str, repo: str, sha: str):
        # Initialize CommitReference using an existing Reference object
        return cls(
            vcs=vcs,
            owner=owner,
            repo=repo,
            sha=sha,
            url=reference.url,
            processed_url=reference.processed_url,
            source=reference.source,
            tags=reference.tags,
            status=reference.status,
            content=reference.content,
            domain=reference.domain
        )

    def to_dict(self):
        base_dict = super().to_dict()
        base_dict.update({
            "vcs": self.vcs,
            "owner": self.owner,
            "repo": self.repo,
            "sha": self.sha
        })

        return base_dict
