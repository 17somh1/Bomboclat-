import json
import logging
import yaml
from censys.search import CensysHosts, CensysCerts
from pycti import OpenCTIConnectorHelper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    with open("config.yml", "r") as file:
        config = yaml.safe_load(file)
    required_keys = ["censys_api_id", "censys_api_secret", "opencti_url", "opencti_token"]
    for key in required_keys:
        if key not in config:
            logger.critical(f"Missing required configuration key: {key}")
            exit(1)
except FileNotFoundError:
    logger.critical("Configuration file 'config.yml' not found. Exiting...")
    exit(1)
except yaml.YAMLError as e:
    logger.critical(f"Error parsing configuration file: {e}")
    exit(1)

try:
    censys_hosts = CensysHosts(api_id=config["censys_api_id"], api_secret=config["censys_api_secret"])
    censys_certs = CensysCerts(api_id=config["censys_api_id"], api_secret=config["censys_api_secret"])
    helper = OpenCTIConnectorHelper(config)
except Exception as e:
    logger.critical(f"Error initializing services: {e}")
    exit(1)


def enrich_ip_address(ip_address):
    try:
        host_details = censys_hosts.view(ip_address)
        return {
            "ip": ip_address,
            "services": host_details.get("services", []),
            "location": host_details.get("location", {}),
            "autonomous_system": host_details.get("autonomous_system", {}),
        }
    except Exception as e:
        logger.error(f"Error enriching IP {ip_address}: {e}")
        return None


def enrich_domain(domain):
    try:
        certificates = list(censys_certs.search(f"parsed.names: {domain}", per_page=5))
        return {"domain": domain, "certificates": certificates}
    except Exception as e:
        logger.error(f"Error enriching domain {domain}: {e}")
        return None


def enrich_certificate(certificate_hash):
    try:
        cert_details = censys_certs.view(certificate_hash)
        return {"certificate": certificate_hash, "details": cert_details}
    except Exception as e:
        logger.error(f"Error enriching certificate {certificate_hash}: {e}")
        return None


def process_message(data):
    if not all(key in data for key in ["entity_type", "entity_id"]):
        logger.warning("Invalid message format: missing 'entity_type' or 'entity_id'")
        return "Invalid message format"

    entity_type = data["entity_type"]
    entity_id = data["entity_id"]

    # Fetch the entity using StixCyberObservable
    entity = helper.api.stix_cyber_observable.read(id=entity_id)
    if not entity:
        logger.warning(f"Entity not found: {entity_id}")
        return f"Entity not found: {entity_id}"

    enrichment_data = None
    entity_value = entity.get("value")
    if entity_type == "IPv4-Addr":
        enrichment_data = enrich_ip_address(entity_value)
        url = f"https://search.censys.io/hosts/{entity_value}"
    elif entity_type == "Domain-Name":
        enrichment_data = enrich_domain(entity_value)
        url = f"https://search.censys.io/certificates?q={entity_value}"
    elif entity_type == "X509-Certificate":
        certificate_hash = entity.get("hashes", {}).get("SHA-256")
        if certificate_hash:
            enrichment_data = enrich_certificate(certificate_hash)
            url = f"https://search.censys.io/certificates/{certificate_hash}"
        else:
            logger.warning(f"No SHA-256 hash found for certificate {entity_id}")
            return f"No SHA-256 hash found for certificate {entity_id}"
    else:
        logger.warning(f"Unsupported entity type: {entity_type}")
        return f"Unsupported entity type: {entity_type}"

    if enrichment_data:
        try:
            # Append to externalReferences using 'add' operation
            helper.api.stix_cyber_observable.update_field(
                id=entity_id,
                key="externalReferences",
                value=[{
                    "source_name": "Censys Enrichment",
                    "url": url,
                    "description": json.dumps(enrichment_data, indent=2),
                }],
                operation='add'
            )
            logger.info(f"Successfully enriched {entity_type} {entity_value}")
            return None  # Indicates success
        except Exception as e:
            logger.error(f"Failed to update OpenCTI entity {entity_id}: {e}")
            return f"Failed to update OpenCTI entity {entity_id}: {e}"
    else:
        logger.info(f"No enrichment data found for {entity_type} {entity_value}")
        return None  # No data is not an error


if __name__ == "__main__":
    try:
        logger.info("Starting Censys OpenCTI connector...")
        helper.listen(process_message)
    except Exception as e:
        logger.critical(f"Error running connector: {e}", exc_info=True)