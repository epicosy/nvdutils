from nvdutils.core.loaders.cna.base import CNABaseLoader


class CNALoader(CNABaseLoader):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mappings = {
            "security_alert@emc.com": "secure@dell.com",
            "security@huntr.dev": "security@huntr.com",
            "chrome-cve-admin@google.com": "security@chromium.org",
            "security@wordfence.com": "cve-request@wordfence.com",
            "cret@cert.org": "cert@cert.org",
            "ykramarz@cisco.com": "psirt@cisco.com",
            "security@android.com": "android-cna-team@google.com",
            "vultures@jpcert.or.jp": "vuls@jpcert.or.jp",
            "securities@openeuler.org": "openeuler-security@openeuler.org",
            "VulnerabilityReporting@secomea.com": "vulnerabilityreporting@secomea.com",
            "mlhess@drupal.org": "security@drupal.org",
            "meissner@suse.de": "security@suse.de",
            "security@zoom.us": "security-reports@zoom.us",
            "cve@jetbrains.com": "security@jetbrains.com",
            "sirt@brocade.com": "brocade.sirt@broadcom.com",
            "bressers@elastic.co": "security@elastic.co",
            "416baaa9-dc9f-4396-8d5f-8c081fb06d67": "cve@kernel.org",
            "twcert@cert.org.tw": "cve@cert.org.tw",
            "PSIRT-CNA@flexerasoftware.com": "psirt-cna@flexerasoftware.com",
            "secure@symantec.com": "symantec.psirt@broadcom.com",
            "a5532a13-c4dd-4202-bef1-e0b8f2f8d12b": "psirt@n-able.com",
            "3836d913-7555-4dd0-a509-f5667fdf5fe4": "security@hihonor.com",
            "security@qnapsecurity.com.tw": "security@qnap.com",
            "iletisim@usom.gov.tr": "cve@usom.gov.tr",
            "0fc0942c-577d-436f-ae8e-945763c79b02": "cna@manageengine.com",
            "vuln@ca.com": "ca.psirt@broadcom.com",
            "cve-coordination@google.com": "alphabet-cna@google.com",
            "dsap-vuln-management@google.com": "dspa-cve@google.com",
            "3c1d8aa1-5a33-4ea4-8992-aadd6440af75": "responsible.disclosure@ivanti.com",
            "ff5b8ace-8b95-4078-9743-eac1ca5451de": "security@concretecms.org",
            "ed10eef1-636d-4fbe-9993-6890dfa878f8": "security@wso2.com",
            "bbf0bd87-ece2-41be-b873-96928ee8fab9": "disclosures@korelogic.com",
            "80f39f49-2521-4ee7-9e17-af5d55e8032f": "secure@upkeeper.se",
            "2499f714-1537-4658-8207-48ae4bb9eae9": "cve@curl.se",
            "fc9afe74-3f80-4fb7-a313-e6f036a89882": "secure.cctv@hanwha.com",
            "0a72a055-908d-47f5-a16a-1f09049c16c6": "cve-coordination@softiron.com",
            "68630edc-a58c-4cbd-9b01-0e130455c8ae": "product-security@asrmicro.com",
            "f86ef6dc-4d3a-42ad-8f28-e6d5547a5007": "cna@postgresql.org",
            "8a9629cb-c5e7-4d2a-a894-111e8039b7ea": "security@opendesign.com",
            "769c9ae7-73c3-4e47-ae19-903170fc3eb8": "security@payara.fish",
            "551230f0-3615-47bd-b7cc-93e92e730bbf": "security-research@sec-consult.com",
            "6b35d637-e00f-4228-858c-b20ad6e1d07b": "security-cna@dfinity.org",
            "1e3a9e0f-5156-4bf8-b8a3-cc311bfc0f4a": "advisory@sba-research.org",
            "4586e0a2-224d-4f8a-9cb4-8882b208c0b3": "product-security@canon-europe.com",
            "5d1c2695-1a31-4499-88ae-e847036fd7e3": "security@watchguard.com",
            "13061848-ea10-403d-bd75-c83a022c2891": "secure@beyondtrust.com",
            "eb41dac7-0af8-4f84-9f6d-0272772514f4": "security@papercut.com",
            "a341c0d1-ebf7-493f-a84e-38cf86618674": "cve-request@cirosec.de",
            "96d4e157-0bf0-48b3-8efd-382c68caf4e0": "security@networkoptix.com",
            "dc3f6da9-85b5-4a73-84a2-2ec90b40fca5": "psirt@microchip.com",
            "907edf6c-bf03-423e-ab1a-8da27e1aa1ea": "security.tecno@tecno-mobile.com",
            "1d66c9f9-fff2-411a-aa19-ca6312fa25e9": "bugs@9front.org",
            "36106deb-8e95-420b-a0a0-e70af5d245df": "psirt@emc.com.tw",
            "85b1779b-6ecd-4f52-bcc5-73eac4659dcf": "psirt@ericsson.com",
            "41c37e40-543d-43a2-b660-2fee83ea851a": "cna@pentraze.com",
            "sec@hillstonenet.com": "psirt@hillstonenet.com",
            "CybersecurityCOE@eaton.com": "psirt@eaton.com",
            "emo@eclipse.org": "security@eclipse.org",
            "jordan@liggitt.net": "security@kubernetes.io",
            "security@puppet.com": "security@perforce.com",
            "psirt-info@cyber.jp.nec.com": "psirt-info@mlsig.jp.nec.com",
            "security@pega.com": "securityreport@pega.com"
        }

    def _get_mapped_email(self, cve_email: str) -> str:
        """Returns the mapped NVD email for a given CVE email, or the original if no mapping exists."""
        return self.mappings.get(cve_email, cve_email)

    def __getitem__(self, key):
        """Override to return the NVD-specific email if it exists."""
        # Check if the original key (CVE email) exists
        if key in self.records:
            return self.records[key]

        # Try to map the key (NVD email) to a CVE email
        mapped_email = self._get_mapped_email(key)

        if mapped_email in self.records:
            return self.records[mapped_email]

        return None
