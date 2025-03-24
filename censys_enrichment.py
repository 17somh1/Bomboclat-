# censys_enrichment.py

import os
from pycti import OpenCTIConnectorHelper
from censys.search import SearchClient
from censys.common.exceptions import CensysException, CensysRateLimitExceededException

class CensysConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({
            "name": "Censys Enrichment",
            "type": "enrichment",
            "update_existing_data": False
        })

        # Read config directly from environment
        self.api_id = os.getenv("CENSYS_API_ID")
        self.api_secret = os.getenv("CENSYS_API_SECRET")

        self.client = SearchClient(api_id=self.api_id, api_secret=self.api_secret)
        self.hosts = self.client.v2.hosts
        self.certs = self.client.v2.certificates

    def _format_result(self, observable_type, observable_value):
        try:
            if observable_type == "IPv4-Addr" or observable_type == "IPv6-Addr":
                host = self.hosts.view(observable_value)
                services = host.get("services", [])
                country = host.get("location", {}).get("country", "N/A")

                markdown = f"## 🔍 Censys Enrichment: IP {observable_value}\n\n"
                markdown += f"**Country:** {country}\n"
                markdown += f"**Open Ports:** {', '.join(str(s['port']) for s in services)}\n\n"
                markdown += "### Services:\n"
                for s in services:
                    port = s.get("port")
                    name = s.get("service_name", "Unknown")
                    product = s.get("software", [{}])[0].get("product") if s.get("software") else "N/A"
                    markdown += f"- Port {port}: {name} ({product})\n"
                return markdown

            elif observable_type == "Domain-Name":
                certs = self.certs.search(f"names: {observable_value}", per_page=2)
                markdown = f"## 🔍 Censys Enrichment: Domain {observable_value}\n\n### Certificates:\n"
                for page in certs:
                    for cert in page:
                        names = ", ".join(cert.get("names", []))
                        issuer = cert.get("issuer", {}).get("organization", "N/A")
                        sha256 = cert.get("fingerprint_sha256", "N/A")
                        valid_from = cert.get("validity", {}).get("start", "N/A")
                        valid_to = cert.get("validity", {}).get("end", "N/A")
                        markdown += f"- **SHA-256:** `{sha256}`\n"
                        markdown += f"  - **Names:** {names}\n"
                        markdown += f"  - **Issuer:** {issuer}\n"
                        markdown += f"  - **Valid:** {valid_from} to {valid_to}\n\n"
                return markdown

            elif observable_type == "X509-Certificate-SHA256":
                cert = self.certs.view(observable_value)
                names = ", ".join(cert.get("names", []))
                issuer = cert.get("issuer", {}).get("organization", "N/A")
                valid_from = cert.get("validity", {}).get("start", "N/A")
                valid_to = cert.get("validity", {}).get("end", "N/A")
                markdown = f"## 🔍 Censys Enrichment: Certificate `{observable_value}`\n\n"
                markdown += f"- **Names:** {names}\n"
                markdown += f"- **Issuer:** {issuer}\n"
                markdown += f"- **Valid:** {valid_from} to {valid_to}\n"
                return markdown

            else:
                return None

        except CensysRateLimitExceededException:
            return "[-] Censys rate limit exceeded"
        except CensysException as e:
            return f"[-] Censys API error: {e}"
        except Exception as e:
            return f"[-] Unexpected error: {str(e)}"

    def _process_observable(self, observable):
        obs_type = observable["entity_type"]
        obs_value = observable["observable_value"]
        self.helper.log_info(f"[Censys] Enriching {obs_type}: {obs_value}")

        work_id = self.helper.api.work.initiate_work(
            name="Censys enrichment",
            data_type="Observable",
            data_id=observable["id"],
        )

        markdown = self._format_result(obs_type, obs_value)

        if markdown:
            self.helper.api.stix_cyber_observable.add_note(
                id=observable["id"],
                content=markdown,
                author="Censys Connector",
                note_type="analysis"
            )
            self.helper.log_info("[Censys] Enrichment successful.")

        else:
            self.helper.log_info(f"[Censys] No data returned for {obs_type}: {obs_value}")

        # Return work_id so OpenCTI can track it
        return work_id

    def run(self):
        self.helper.listen(self._process_observable)

if __name__ == "__main__":
    connector = CensysConnector()
    connector.run()
