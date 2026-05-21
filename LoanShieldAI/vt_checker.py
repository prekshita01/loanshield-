import os
import base64
import requests
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class VTChecker:
    def __init__(self, api_key=None):
        # Allow loading from environment variable if not passed
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"

    def _get_domain(self, url):
        """Helper to extract domain from a URL."""
        if not url:
            return ""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            return ""

    def check_domain(self, url):
        """
        Queries VirusTotal for domain reputation.
        Returns a dict containing threat details and a threat score (0-100).
        """
        domain = self._get_domain(url)
        if not domain:
            return {
                "scanned": False,
                "threat_score": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "verdict": "CLEAN",
                "details": "Invalid URL or domain",
                "is_mock": False
            }

        # If no API key, return mock simulation data based on domain heuristics
        if not self.api_key:
            return self._simulate_threat_report(domain)

        headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }
        
        try:
            # Query domain endpoint
            api_endpoint = f"{self.base_url}/domains/{domain}"
            response = requests.get(api_endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                
                # Threat score calculation:
                # Weight: Malicious = 10 points each, Suspicious = 5 points each (max 100)
                threat_score = min((malicious * 20) + (suspicious * 10), 100)
                
                verdict = "CLEAN"
                if malicious > 2 or threat_score >= 40:
                    verdict = "MALICIOUS"
                elif malicious > 0 or suspicious > 1:
                    verdict = "SUSPICIOUS"

                return {
                    "scanned": True,
                    "threat_score": threat_score,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_vendors": total,
                    "verdict": verdict,
                    "details": f"VirusTotal scanning completed for domain {domain}.",
                    "is_mock": False,
                    "categories": data.get("data", {}).get("attributes", {}).get("categories", {})
                }
            elif response.status_code == 404:
                # Domain not analyzed yet
                return {
                    "scanned": True,
                    "threat_score": 0,
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "harmless_count": 0,
                    "total_vendors": 0,
                    "verdict": "CLEAN",
                    "details": f"Domain {domain} is not yet indexed in VirusTotal database.",
                    "is_mock": False
                }
            else:
                logger.error(f"VirusTotal API returned error {response.status_code}: {response.text}")
                # Fallback to simulation on API error
                return self._simulate_threat_report(domain, error_fallback=True)
                
        except Exception as e:
            logger.error(f"Error calling VirusTotal API: {e}")
            return self._simulate_threat_report(domain, error_fallback=True)

    def _simulate_threat_report(self, domain, error_fallback=False):
        """Generates realistic simulation data for demonstration or fallback purposes."""
        # Simple heuristic risk determination
        is_suspicious_tld = any(domain.endswith(tld) for tld in ['.xyz', '.cc', '.top', '.loan', '.click', '.club', '.gq', '.cf', '.tk', '.ml'])
        has_scam_keywords = any(kw in domain.lower() for kw in ['rupee', 'cash', 'loan', 'instant', 'quick', 'fast', 'wallet', 'credit'])
        
        malicious = 0
        suspicious = 0
        
        # If it has a bad TLD AND scam keywords, simulate high risk
        if is_suspicious_tld and has_scam_keywords:
            malicious = 5
            suspicious = 3
        elif is_suspicious_tld:
            malicious = 1
            suspicious = 2
        elif has_scam_keywords:
            # Check if domain looks like a genuine financial site or a subdomain
            if "bajaj" in domain or "tata" in domain or "navi" in domain or "dmi" in domain:
                malicious = 0
                suspicious = 0
            else:
                suspicious = 2
                
        total_vendors = 89
        threat_score = min((malicious * 20) + (suspicious * 10), 100)
        
        verdict = "CLEAN"
        if malicious >= 2 or threat_score >= 40:
            verdict = "MALICIOUS"
        elif malicious > 0 or suspicious > 0:
            verdict = "SUSPICIOUS"
            
        source_desc = "API Error Fallback Simulation" if error_fallback else "Demonstration Mode (No VT_API_KEY provided)"
        
        return {
            "scanned": True,
            "threat_score": threat_score,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": total_vendors - malicious - suspicious,
            "total_vendors": total_vendors,
            "verdict": verdict,
            "details": f"[{source_desc}] Scanned domain: {domain}. Heuristic scan identifies potential flags based on patterns.",
            "is_mock": True,
            "categories": {"reputation": "Financial Services (Unverified)" if threat_score > 30 else "Information Technology"}
        }
