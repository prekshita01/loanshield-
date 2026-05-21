import re
import logging
from urllib.parse import urlparse, parse_qs
# pyrefly: ignore [missing-import]
try:
    from google_play_scraper import app as play_scraper_app, search as play_scraper_search, reviews as play_scraper_reviews
    SCRAPER_AVAILABLE = True
except ImportError as e:
    logging.error(f"google_play_scraper import failed: {e}")
    SCRAPER_AVAILABLE = False


from vt_checker import VTChecker
from osint import OSINTAnalyzer
from rbi_checker import RBIChecker
from risk_engine import RiskEngine

logger = logging.getLogger(__name__)

class AppAnalyzer:
    def __init__(self, vt_api_key=None):
        self.vt = VTChecker(api_key=vt_api_key)
        self.osint = OSINTAnalyzer()
        self.rbi = RBIChecker()
        self.risk = RiskEngine()

    def extract_package_name(self, input_string):
        """
        Extracts Android package name from a Play Store URL or returns the input
        if it matches package name format.
        """
        input_string = input_string.strip()
        
        # Check if URL
        if input_string.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(input_string)
                # Play store web format: details?id=com.package.name
                if "play.google.com" in parsed.netloc and "details" in parsed.path:
                    query_params = parse_qs(parsed.query)
                    if 'id' in query_params:
                        return query_params['id'][0]
            except Exception as e:
                logger.error(f"Error parsing URL: {e}")
                
        # Pattern match for package name (e.g. com.example.app)
        package_pattern = r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$'
        if re.match(package_pattern, input_string):
            return input_string
            
        return None

    def fetch_play_store_details(self, input_query):
        """
        Attempts to scrape metadata from Google Play Store.
        If a package name is not provided, searches by app name first.
        If scraping fails, generates a mock fallback.
        """
        package_name = self.extract_package_name(input_query)
        search_used = False

        if not package_name and SCRAPER_AVAILABLE:
            # Assume it is an App Name, perform search
            try:
                search_results = play_scraper_search(input_query, lang="en", country="in")
                if search_results:
                    package_name = search_results[0].get("appId")
                    search_used = True
                    logger.info(f"Searched for '{input_query}' and found package: {package_name}")
                else:
                    logger.warning(f"No search results for app name: {input_query}")
            except Exception as e:
                logger.error(f"Error searching Play Store: {e}")

        # If we have a package name, attempt to scrape details
        app_details = None
        reviews_list = []
        
        if package_name and SCRAPER_AVAILABLE:
            try:
                app_details = play_scraper_app(package_name, lang="en", country="in")
                
                # Fetch recent reviews
                try:
                    rv_results, _ = play_scraper_reviews(
                        package_name,
                        lang='en',
                        country='in'
                    )
                    # Limit to top 5 reviews manually to avoid kwarg issues
                    reviews_list = [{"text": r.get("content", ""), "rating": r.get("score", 0)} for r in rv_results[:5]]
                except Exception as rev_err:
                    logger.warning(f"Failed to fetch reviews: {rev_err}")
                    
            except Exception as e:
                logger.warning(f"Could not scrape details for package {package_name}: {e}")

        # Return real data or fallback mock data
        if app_details:
            return {
                "app_name": app_details.get("title", ""),
                "package_name": package_name,
                "developer_name": app_details.get("developer", ""),
                "developer_email": app_details.get("developerEmail", ""),
                "developer_website": app_details.get("developerWebsite", ""),
                "installs": app_details.get("installs", "0+"),
                "ratings": app_details.get("score", 0.0),
                "privacy_policy_url": app_details.get("privacyPolicy", ""),
                "permissions": app_details.get("permissions", []),
                "description": app_details.get("description", ""),
                "last_update_date": app_details.get("updated", ""),
                "reviews_list": reviews_list,
                "is_mock": False
            }
        else:
            # Return smart simulated fallback
            clean_name = input_query if not package_name else package_name.split('.')[-1].replace('_', ' ').title()
            sim_package = package_name or f"com.loan.{clean_name.lower().replace(' ', '')}"
            
            # If the name looks suspicious or standard scam, simulate scam app details
            is_suspicious_query = any(kw in input_query.lower() for kw in ['rupee', 'cash', 'instant', 'quick', 'easy', 'wallet', 'pocket'])
            
            if is_suspicious_query:
                sim_dev_website = f"http://{clean_name.lower().replace(' ', '')}-loans.xyz"
                sim_privacy = f"https://sites.google.com/view/{clean_name.lower().replace(' ', '')}-privacy/home"
                sim_description = (
                    f"Welcome to {clean_name} - your instant personal loan partner! Get loans from ₹5,000 to ₹50,000 in 5 minutes! "
                    "Low interest rates starting from 0.05% per day. Repayment tenure from 91 to 365 days. "
                    "Permissions required: Contacts, SMS, Storage for credit check."
                )
                sim_permissions = [
                    "android.permission.READ_CONTACTS",
                    "android.permission.READ_SMS",
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.ACCESS_FINE_LOCATION"
                ]
                sim_rating = 2.8
                sim_reviews = [
                    {"text": "Very bad app! They are harassing me and calling my contact list for recovery. Fraud app!", "rating": 1},
                    {"text": "High interest rates and processing fees. Don't download this, they steal data.", "rating": 1},
                    {"text": "Good loan instant approval.", "rating": 5}
                ]
            else:
                # Simulate a genuine-looking app
                sim_dev_website = f"https://www.{clean_name.lower().replace(' ', '')}finance.in"
                sim_privacy = f"{sim_dev_website}/privacy-policy"
                sim_description = (
                    f"{clean_name} is a leading digital lending application partnered with RBI-registered NBFCs. "
                    "We offer personal loans with fully transparent charges. Repayment tenure ranges from 6 to 24 months. "
                    "Interest rates (APR) range from 12% to 28% per annum. Representative calculation: loan amount ₹10,000 with APR 18%. "
                    "For support or complaints, contact our Grievance Redressal Officer at complaints@dev.in."
                )
                sim_permissions = [
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_COARSE_LOCATION"
                ]
                sim_rating = 4.2
                sim_reviews = [
                    {"text": "Easy approval and very transparent process. Recommended.", "rating": 5},
                    {"text": "Excellent service and reasonable interest rates compared to others.", "rating": 4}
                ]

            return {
                "app_name": clean_name,
                "package_name": sim_package,
                "developer_name": f"{clean_name} Fintech Pvt Ltd",
                "developer_email": f"support@{clean_name.lower().replace(' ', '')}finance.in",
                "developer_website": sim_dev_website,
                "installs": "100,000+" if not is_suspicious_query else "10,000+",
                "ratings": sim_rating,
                "privacy_policy_url": sim_privacy,
                "permissions": sim_permissions,
                "description": sim_description,
                "last_update_date": "May 10, 2026",
                "reviews_list": sim_reviews,
                "is_mock": True,
                "fallback_reason": "App not found on Play Store (possibly removed) or network offline. Simulated audit profile generated."
            }

    def run_analysis(self, input_query, db_session=None):
        """
        Executes the full pipeline:
        1. Fetch Play Store App details
        2. Run VirusTotal Domain check on Developer Website
        3. Run OSINT domain analyzer
        4. Run RBI compliance engine
        5. Run final risk scorer
        """
        # Step 1: Scrape / Simulate Play Store details
        app_info = self.fetch_play_store_details(input_query)
        dev_site = app_info.get("developer_website", "")
        privacy_site = app_info.get("privacy_policy_url", "")
        
        # Step 2: VirusTotal threat check (using dev website)
        # If no dev website, fall back to checking privacy policy domain
        vt_target = dev_site or privacy_site
        vt_results = self.vt.check_domain(vt_target)
        
        # Step 3: Run OSINT checker
        osint_results = self.osint.analyze(vt_target)
        
        # Step 4: Run RBI compliance checks
        rbi_results = self.rbi.check_compliance(app_info, db_session=db_session)
        
        # Step 5: Risk calculations
        risk_results = self.risk.calculate_risk(app_info, vt_results, rbi_results, osint_results)
        
        # Combine everything
        return {
            "app_info": app_info,
            "vt_results": vt_results,
            "osint_results": osint_results,
            "rbi_results": rbi_results,
            "risk_results": risk_results
        }
