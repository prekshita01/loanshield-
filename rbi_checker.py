import re
from database import NBFCList
import urllib.parse

class RBIChecker:
    def __init__(self):
        pass

    def check_compliance(self, app_data, db_session=None):
        """
        Evaluates RBI Digital Lending Guidelines compliance.
        app_data should contain keys:
          - description: App description text
          - developer_website: Developer website URL
          - privacy_policy_url: Privacy Policy URL
          - permissions: List of permissions requested by the app (e.g. ['android.permission.READ_CONTACTS'])
          - developer_name: Name of the developer
        """
        description = app_data.get("description", "") or ""
        dev_website = app_data.get("developer_website", "") or ""
        privacy_url = app_data.get("privacy_policy_url", "") or ""
        permissions = app_data.get("permissions", []) or []
        dev_name = app_data.get("developer_name", "") or ""

        findings = []
        checks = {}
        score = 100

        # 1. RBI Registered NBFC Association & Lender Disclosure
        # Check if the app lists a registered NBFC partner
        nbfc_partner = None
        has_disclosure = False
        
        # Pull registered NBFCs from DB if session is available
        registered_nbfcs = []
        if db_session:
            try:
                registered_nbfcs = db_session.query(NBFCList).all()
            except Exception:
                pass
        
        # If DB check failed or empty, fallback to basic hardcoded check list
        if not registered_nbfcs:
            # Simple list of keywords for check
            nbfc_keywords = [
                "Bajaj Finance", "DMI Finance", "Aditya Birla Finance", "Tata Capital", 
                "L&T Finance", "Muthoot Fincorp", "InCred", "Krazybee", "Saison Finance",
                "Northern Arc", "Earlysalary", "Fibe", "PayU Finance", "IIFL Finance", 
                "Manappuram Finance", "Navi Finserv"
            ]
        else:
            nbfc_keywords = [n.nbfc_name for n in registered_nbfcs]

        # Scan description and dev name for NBFC associations
        desc_lower = description.lower()
        dev_name_lower = dev_name.lower()
        
        for nbfc in nbfc_keywords:
            # Check for exact matches
            if nbfc.lower() in desc_lower or nbfc.lower() in dev_name_lower:
                nbfc_partner = nbfc
                has_disclosure = True
                break

        # Check if developer website matches a registered NBFC website
        dev_domain = ""
        if dev_website:
            try:
                parsed = urllib.parse.urlparse(dev_website)
                dev_domain = (parsed.netloc or parsed.path.split('/')[0]).lower().replace('www.', '')
            except Exception:
                pass

        if db_session and registered_nbfcs:
            for nbfc in registered_nbfcs:
                if nbfc.website:
                    nbfc_web = nbfc.website.lower().replace('www.', '')
                    if dev_domain and (dev_domain in nbfc_web or nbfc_web in dev_domain):
                        nbfc_partner = nbfc.nbfc_name
                        has_disclosure = True
                        break

        if has_disclosure:
            checks["lender_disclosure"] = True
            findings.append(f"Lender Disclosed: App is associated with RBI registered partner '{nbfc_partner}'")
        else:
            checks["lender_disclosure"] = False
            score -= 25
            findings.append("Lender Non-Disclosure: No association with an RBI registered NBFC/Bank could be verified in the app details.")

        # 2. Interest Rate & Fee Transparency
        # Look for keywords about APR, interest rates, charges, processing fees, loan tenure
        transparency_keywords = ["apr", "interest rate", "processing fee", "tenure", "repayment", "annual percentage"]
        matching_keywords = [kw for kw in transparency_keywords if kw in desc_lower]
        
        # Check if description contains representative example loan calculation (mandated by RBI)
        has_example = "example" in desc_lower or "calculation" in desc_lower or "principle" in desc_lower or "tenor" in desc_lower
        
        if len(matching_keywords) >= 3 and has_example:
            checks["interest_rate_transparency"] = True
            findings.append("Interest Rate Transparency: Detailed disclosure of APR, tenures, processing fees, and illustrative loan examples found.")
        else:
            checks["interest_rate_transparency"] = False
            score -= 15
            findings.append("Low Transparency: Description lacks details on APR, repayment tenure, processing charges, or an illustrative example.")

        # 3. Grievance Redressal Mechanism
        # Look for grievance officer details, email or contact
        grievance_match = re.search(r'(grievance|nodal|redressal|complaint|officer)', desc_lower)
        # We can also search in dev_website later if we crawl, but check description first
        if grievance_match:
            checks["grievance_officer"] = True
            findings.append("Grievance Redressal: Grievance details or contact officer mentioned in metadata.")
        else:
            checks["grievance_officer"] = False
            score -= 15
            findings.append("No Grievance Redressal details: No grievance officer contact or nodal officer listed in the description.")

        # 4. Privacy Policy Existence & Quality Check
        if privacy_url and privacy_url.strip():
            # Check if hosted on suspicious free domains or cloud storage links (typical of fake apps)
            suspicious_policy_hosts = ['drive.google.com', 'dropbox.com', 'blogspot.com', 'wordpress.com', 'github.io', 'sites.google.com', 'pastebin.com', 'docs.google.com']
            is_suspicious_host = any(host in privacy_url.lower() for host in suspicious_policy_hosts)
            
            if is_suspicious_host:
                checks["privacy_policy"] = "SUSPICIOUS"
                score -= 15
                findings.append(f"Suspicious Privacy Policy Hosting: Policy URL ({privacy_url}) is hosted on a free/cloud service, a common tactic for ephemeral fraud apps.")
            else:
                checks["privacy_policy"] = "VALID"
                findings.append("Privacy Policy: Valid dedicated privacy policy URL provided.")
        else:
            checks["privacy_policy"] = "MISSING"
            score -= 20
            findings.append("Missing Privacy Policy: No privacy policy URL disclosed. This violates Google Play Store and RBI guidelines.")

        # 5. Data Access Restrictions (Critical RBI Guideline)
        # Digital lending apps are NOT allowed to access contacts, call logs, SMS, storage/photos
        bad_permissions = []
        contacts_perms = [p for p in permissions if 'contacts' in p.lower()]
        sms_perms = [p for p in permissions if 'sms' in p.lower()]
        storage_perms = [p for p in permissions if 'storage' in p.lower() or 'external_media' in p.lower() or 'read_media' in p.lower()]
        location_perms = [p for p in permissions if 'location' in p.lower()]
        
        if contacts_perms:
            bad_permissions.append("Contacts Access")
            score -= 15
        if sms_perms:
            bad_permissions.append("SMS Access")
            score -= 15
        if storage_perms:
            bad_permissions.append("Storage/Media Access")
            score -= 10
        if location_perms:
            bad_permissions.append("Location Access")
            score -= 5 # Location is sometimes allowed for KYC, but excessive requests are restricted
            
        if bad_permissions:
            checks["data_access_compliance"] = False
            findings.append(f"RBI Non-Compliance (Data Access): App requests restricted resources: {', '.join(bad_permissions)}. RBI rules prohibit access to contacts, SMS, and storage.")
        else:
            checks["data_access_compliance"] = True
            findings.append("Data Access Compliance: App does not request unauthorized access to contacts, SMS, or local storage.")

        # 6. Recovery Practices transparency
        recovery_threats = ["harass", "abuse", "agent", "force", "threaten"]
        found_threats = [kw for kw in recovery_threats if kw in desc_lower]
        
        # Genuine loan apps mention a standard recovery process or no harassment
        if len(found_threats) > 0:
            checks["recovery_practices"] = False
            score -= 10
            findings.append("Suspicious Recovery Language: Keywords indicating aggressive collection or recovery policies found.")
        else:
            checks["recovery_practices"] = True
            findings.append("Recovery Practices: No aggressive collection or threat keywords found in description.")

        # Final scoring and status
        score = max(0, score)
        if score >= 80:
            status = "PASS"
        elif score >= 50:
            status = "WARNING"
        else:
            status = "FAIL"

        return {
            "compliance_score": score,
            "compliance_status": status,
            "checks": checks,
            "findings": findings
        }
