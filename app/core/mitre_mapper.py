import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class MitreMapper:
    # Static mapping from scanner findings to MITRE ATT&CK technique IDs
    FINDING_TO_TECHNIQUE = {
        "SMBv1_Status": "T1210",
        "Unquoted_Services": "T1574.009",
        "UAC_Check": "T1548.002",
        "FileSystem_Check": "T1222.001",
        "Network_Scan": "T1046" # Adding Network scanning to discovery
    }

    def __init__(self, cache_file: str = "mitre_cache.json"):
        self.cache_file = cache_file
        self.cache: Dict[str, Any] = {}
        self.load_cache()

    def load_cache(self) -> None:
        """Loads the MITRE technique cache from disk if it exists."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                logger.debug(f"Loaded MITRE cache from {self.cache_file}")
            except Exception as e:
                logger.error(f"Error loading MITRE cache: {e}")
                self.cache = {}
        else:
            logger.info(f"MITRE cache {self.cache_file} not found. Call update_cache() to create it.")

    def save_cache(self) -> None:
        """Saves the current cache to disk."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=4)
            logger.info(f"Saved MITRE cache to {self.cache_file}")
        except Exception as e:
            logger.error(f"Error saving MITRE cache: {e}")

    def update_cache(self) -> None:
        """
        Fetches the latest Enterprise ATT&CK matrix using attackcti
        and updates the local JSON cache.
        """
        try:
            from attackcti import attack_client
            client = attack_client()
            logger.info("Fetching MITRE ATT&CK techniques... this may take a moment.")
            techniques = client.get_enterprise_techniques()
            
            new_cache = {}
            for t in techniques:
                # STIX 2 objects have external_references
                ext_refs = t.get('external_references', [])
                mitre_id = None
                url = None
                for ref in ext_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        mitre_id = ref.get('external_id')
                        url = ref.get('url')
                        break
                        
                if not mitre_id:
                    continue
                    
                name = t.get('name', 'Unknown')
                description = t.get('description', 'No description available')
                deprecated = t.get('x_mitre_deprecated', False)
                revoked = t.get('revoked', False)
                
                new_cache[mitre_id] = {
                    "id": mitre_id,
                    "name": name,
                    "description": description,
                    "url": url,
                    "deprecated": deprecated,
                    "revoked": revoked,
                }
                
            self.cache = new_cache
            self.save_cache()
            logger.info(f"Successfully updated MITRE cache with {len(self.cache)} techniques.")
        except ImportError:
            logger.error("attackcti is not installed. Please install it to update the MITRE cache.")
        except Exception as e:
            logger.error(f"Error updating MITRE cache: {e}")

    def get_technique_details(self, finding_key: str) -> Optional[Dict[str, Any]]:
        """
        Given a finding key from the scanner, returns the enriched MITRE ATT&CK details
        if a mapping exists.
        """
        technique_id = self.FINDING_TO_TECHNIQUE.get(finding_key)
        if not technique_id:
            return None
            
        details = self.cache.get(technique_id)
        if details:
            # Handle if the technique is revoked or deprecated gracefully
            if details.get("revoked") or details.get("deprecated"):
                logger.warning(f"Technique {technique_id} mapped to {finding_key} is deprecated/revoked in MITRE ATT&CK.")
            return details
            
        # Fallback if the cache hasn't been updated yet, but we know the mapping
        return {
            "id": technique_id,
            "name": "Metadata unavailable",
            "description": "Run cache update to fetch details for this technique.",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            "deprecated": False,
            "revoked": False
        }

    def enrich_report(self, report_data: Any) -> Any:
        """
        Recursively maps finding keys in report_data and attaches MITRE data
        to the dictionaries where they were found or at the top level.
        """
        if isinstance(report_data, dict):
            # To avoid mutating during iteration
            keys = list(report_data.keys())
            mitre_list = []
            for k in keys:
                details = self.get_technique_details(k)
                if details:
                    mitre_list.append({k: details})
                
                # Recurse
                report_data[k] = self.enrich_report(report_data[k])
                
            if mitre_list:
                if "mitre_techniques" not in report_data:
                    report_data["mitre_techniques"] = mitre_list
                else:
                    report_data["mitre_techniques"].extend(mitre_list)
                    
            return report_data
            
        elif isinstance(report_data, list):
            return [self.enrich_report(item) for item in report_data]
            
        return report_data
