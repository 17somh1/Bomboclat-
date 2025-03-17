# Import necessary libraries
import json  # For working with JSON data
import logging  # For logging messages
import yaml  # For parsing YAML configuration files
from censys.search import CensysHosts, CensysCerts  # Censys API clients
from pycti import OpenCTIConnectorHelper, StixCyberObservable  # OpenCTI helper and STIX classes

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)  # Create a logger for the module


class ConfigConnector:
    """
    Handles loading and validating the connector configuration from a YAML file.
    """

    def __init__(self):
        try:
            # Load configuration from config.yml
            with open("config.yml", "r") as file:
                self.config = yaml.safe_load(file)

            # Define required configuration keys
            required_keys = [
                "censys_api_id", "censys_api_secret",
                "opencti_url", "opencti_token", "connector_id"
            ]

            # Validate that all required keys are present
            for key in required_keys:
                if key not in self.config:
                    logger.critical(f"Missing required configuration key: {key}")
                    exit(1)

            # Set default values for optional configuration parameters
            self.config.setdefault("connector_scope", ["IPv4-Addr", "Domain-Name", "X509-Certificate"])
            self.config.setdefault("max_tlp", "TLP:AMBER")

        except FileNotFoundError:
            logger.critical("Configuration file 'config.yml' not found. Exiting...")
            exit(1)
        except yaml.YAMLError as e:
            logger.critical(f"Error parsing configuration file: {e}")
            exit(1)

    @property
    def load(self):
        """
        Returns the loaded configuration.
        """
        return self.config


class ConnectorClient:
    """
    Handles interactions with the Censys API for enriching observables.
    """

    def __init__(self, helper, config):
        """
        Initializes the Censys API clients using the provided credentials.
        """
        self.helper = helper
        self.censys_hosts = CensysHosts(
            api_id=config["censys_api_id"],
            api_secret=config["censys_api_secret"]
        )
        self.censys_certs = CensysCerts(
            api_id=config["censys_api_id"],
            api_secret=config["censys_api_secret"]
        )

    def enrich_ip(self, ip_address):
        """
        Enriches an IP address using Censys Hosts API.
        """
        try:
            # Fetch host details from Censys
            host = self.censys_hosts.view(ip_address)
            return {
                "services": host.get("services", []),  # List of services running on the host
                "location": host.get("location", {}),  # Geographic location of the host
                "autonomous_system": host.get("autonomous_system", {})  # ASN details
            }
        except Exception as e:
            self.helper.connector_logger.error(f"IP enrichment failed: {str(e)}")
            return None

    def enrich_domain(self, domain):
        """
        Enriches a domain name using Censys Certificates API.
        """
        try:
            # Search for certificates associated with the domain
            certs = list(self.censys_certs.search(f"parsed.names: {domain}", per_page=5))
            return {"certificates": [c["parsed"] for c in certs]}  # Extract parsed certificate details
        except Exception as e:
            self.helper.connector_logger.error(f"Domain enrichment failed: {str(e)}")
            return None

    def enrich_certificate(self, fingerprint):
        """
        Enriches a certificate using Censys Certificates API.
        """
        try:
            # Fetch certificate details from Censys
            cert = self.censys_certs.view(fingerprint)
            return {
                "subject": cert.get("parsed", {}).get("subject", {}),  # Certificate subject
                "issuer": cert.get("parsed", {}).get("issuer", {}),  # Certificate issuer
                "validity": cert.get("parsed", {}).get("validity", {})  # Certificate validity period
            }
        except Exception as e:
            self.helper.connector_logger.error(f"Certificate enrichment failed: {str(e)}")
            return None


class ConverterToStix:
    """
    Handles conversion of enriched data into STIX format.
    """

    def __init__(self, helper):
        self.helper = helper

    def create_external_reference(self, url, description):
        """
        Creates a STIX external reference object.
        """
        return {
            "source_name": "Censys Enrichment",  # Name of the enrichment source
            "url": url,  # URL to the enrichment data
            "description": json.dumps(description, indent=2)  # Enrichment details in JSON format
        }

    def update_observable(self, observable, external_ref):
        """
        Updates a STIX observable with a new external reference.
        """
        updated = observable.copy()  # Create a copy of the original observable
        updated.setdefault("external_references", [])  # Initialize external_references if missing
        updated["external_references"].append(external_ref)  # Add the new reference
        return updated


class CensysConnector:
    """
    Main connector class that integrates with OpenCTI and Censys.
    """

    def __init__(self):
        """
        Initializes the connector with configuration, helper, and clients.
        """
        self.config = ConfigConnector().load  # Load configuration
        self.helper = OpenCTIConnectorHelper(self.config)  # Initialize OpenCTI helper
        self.client = ConnectorClient(self.helper, self.config)  # Initialize Censys client
        self.converter = ConverterToStix(self.helper)  # Initialize STIX converter

    def _process_observable(self, observable):
        """
        Processes an observable based on its type and enriches it using Censys.
        """
        entity_type = observable["entity_type"]  # Get the observable type (e.g., IPv4-Addr)
        value = observable["value"]  # Get the observable value (e.g., IP address)
        result = None
        url = None

        # Enrich based on observable type
        if entity_type == "IPv4-Addr":
            result = self.client.enrich_ip(value)
            url = f"https://search.censys.io/hosts/{value}"  # URL to Censys host details
        elif entity_type == "Domain-Name":
            result = self.client.enrich_domain(value)
            url = f"https://search.censys.io/certificates?q={value}"  # URL to Censys certificate search
        elif entity_type == "X509-Certificate":
            sha256 = observable.get("hashes", {}).get("SHA-256")  # Get certificate fingerprint
            if sha256:
                result = self.client.enrich_certificate(sha256)
                url = f"https://search.censys.io/certificates/{sha256}"  # URL to Censys certificate details

        # If enrichment data is found, create a STIX observable
        if result and url:
            external_ref = self.converter.create_external_reference(url, result)
            updated_obs = self.converter.update_observable(observable, external_ref)
            return StixCyberObservable(**updated_obs)  # Convert to STIX format
        return None

    def _process_message(self, data):
        """
        Processes a message from OpenCTI and enriches the observable.
        """
        try:
            observable_id = data["entity_id"]  # Get the observable ID
            observable = self.helper.api.stix_cyber_observable.read(id=observable_id)  # Fetch observable details

            if not observable:
                self.helper.connector_logger.error("Observable not found")
                return None

            # Check if the observable's TLP allows processing
            if not self.helper.check_max_tlp(observable.get("objectMarking"), self.config["max_tlp"]):
                self.helper.connector_logger.warning("Skipping due to TLP restrictions")
                return None

            # Process the observable and create a STIX bundle
            stix_obs = self._process_observable(observable)
            if stix_obs:
                bundle = self.helper.stix2_create_bundle([stix_obs])  # Create STIX bundle
                self.helper.send_stix2_bundle(bundle)  # Send bundle to OpenCTI
                return f"Enriched {observable['value']}"  # Return success message
            return "No enrichment data found"  # Return if no enrichment data is found
        except Exception as e:
            self.helper.connector_logger.error(str(e))  # Log any errors
            return None

    def start(self):
        """
        Starts the connector and listens for messages from OpenCTI.
        """
        self.helper.listen(self._process_message)  # Begin listening for observable updates


if __name__ == "__main__":
    try:
        logger.info("Starting Censys connector...")
        connector = CensysConnector()  # Initialize the connector
        connector.start()  # Start the connector
    except Exception as e:
        logger.critical(f"Connector failed: {str(e)}")  # Log critical errors
        exit(1)