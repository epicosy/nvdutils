from dataclasses import dataclass


@dataclass
class CNA:
    id: str
    name: str
    root: str
    vendor_names: list
    security_links: dict
    is_vendor: bool
    is_researcher: bool
    is_open_source: bool
    is_cert: bool
    is_hosted_service: bool
    is_bug_bounty_provider: bool
    is_consortium: bool
    github_owner: str = None

    def __str__(self):
        return f"{self.id} {self.name} {self.root} {self.vendor_names} {self.security_links} {self.is_vendor} " \
               f"{self.is_researcher} {self.is_open_source} {self.is_cert} {self.is_hosted_service} " \
               f"{self.is_bug_bounty_provider} {self.is_consortium} {self.github_owner}"
