class RiskEngine:
    def __init__(self):
        pass

    def calculate_risk(self, play_store_info, vt_results, compliance_results, osint_results):
        """
        Calculates a final weighted fraud risk score (0-100) and returns classification.
        
        Weights:
        1. VirusTotal Detections (Max 40 points)
        2. RBI Non-Compliance (Max 30 points)
        3. OSINT / URL Suspicion (Max 20 points)
        4. Dangerous Permissions (Max 20 points)
        5. User Ratings / Complaints Heuristics (Max 10 points)
        
        Total potential raw score can be up to 120 points, but it is capped at 100.
        """
        breakdown = {}
        
        # 1. VirusTotal Score (Max 40)
        vt_score = vt_results.get("threat_score", 0)
        vt_weighted = round((vt_score / 100.0) * 40.0)
        breakdown["vt_threat"] = {
            "score": vt_score,
            "weighted": vt_weighted,
            "max": 40,
            "description": f"VirusTotal threat flags (Score: {vt_score}/100)"
        }

        # 2. RBI Non-Compliance Score (Max 30)
        # Low compliance = High risk
        compliance_score = compliance_results.get("compliance_score", 100)
        non_compliance = 100 - compliance_score
        rbi_weighted = round((non_compliance / 100.0) * 30.0)
        breakdown["rbi_non_compliance"] = {
            "score": non_compliance,
            "weighted": rbi_weighted,
            "max": 30,
            "description": f"RBI guidelines violations (Compliance: {compliance_score}/100)"
        }

        # 3. OSINT / URL Score (Max 20)
        osint_score = osint_results.get("risk_score", 0)
        osint_weighted = round((osint_score / 100.0) * 20.0)
        breakdown["osint_reputation"] = {
            "score": osint_score,
            "weighted": osint_weighted,
            "max": 20,
            "description": f"Domain / URL OSINT anomalies (Score: {osint_score}/100)"
        }

        # 4. Dangerous Permissions (Max 20)
        # Google Play Store guidelines & RBI prohibit loan apps accessing contacts, SMS, call logs, storage.
        permissions = play_store_info.get("permissions", []) or []
        perm_score = 0
        contacts = False
        sms = False
        storage = False
        location = False
        
        for perm in permissions:
            perm_lower = perm.lower()
            if "contacts" in perm_lower:
                contacts = True
            elif "sms" in perm_lower:
                sms = True
            elif "storage" in perm_lower or "external_media" in perm_lower or "read_media" in perm_lower:
                storage = True
            elif "location" in perm_lower:
                location = True

        if contacts:
            perm_score += 8  # Contacts is a critical warning (usually abused for harassment)
        if sms:
            perm_score += 6  # SMS allows monitoring bank alerts
        if storage:
            perm_score += 4  # Storage allows stealing photos
        if location:
            perm_score += 2  # Location tracking
            
        perm_score = min(perm_score, 20)
        # Map out of 100 first, then apply weight
        perm_percentage = (perm_score / 20.0) * 100
        perm_weighted = perm_score
        breakdown["dangerous_permissions"] = {
            "score": int(perm_percentage),
            "weighted": perm_weighted,
            "max": 20,
            "description": f"Restricted android resource requests"
        }

        # 5. User Ratings / Complaints Heuristics (Max 10)
        # Check rating & review complaint keywords
        rating = play_store_info.get("ratings", 5.0) or 5.0
        reviews = play_store_info.get("reviews_list", []) or []
        
        rating_risk = 0
        if rating < 3.0:
            rating_risk += 5
        elif rating < 3.8:
            rating_risk += 3
            
        # Review keywords check
        complaint_keywords = ["scam", "fraud", "hacked", "threat", "harass", "fake", "abuse", "blackmail", "torture", "interest high", "cheat"]
        complaint_count = 0
        
        # Combine app description and user reviews to look for indicators
        combined_text = " ".join([r.get("text", "").lower() for r in reviews])
        
        for kw in complaint_keywords:
            if kw in combined_text:
                complaint_count += 1
                
        if complaint_count >= 3:
            rating_risk += 5
        elif complaint_count >= 1:
            rating_risk += 3
            
        rating_risk = min(rating_risk, 10)
        rating_percentage = (rating_risk / 10.0) * 100
        rating_weighted = rating_risk
        breakdown["user_feedback"] = {
            "score": int(rating_percentage),
            "weighted": rating_weighted,
            "max": 10,
            "description": f"Low rating & negative user reviews"
        }

        # Final Score Calculation (Capped at 100)
        final_score = vt_weighted + rbi_weighted + osint_weighted + perm_weighted + rating_weighted
        final_score = min(final_score, 100)

        # Final Verdict Classification
        if final_score <= 30:
            verdict = "SAFE"
        elif final_score <= 60:
            verdict = "SUSPICIOUS"
        else:
            verdict = "HIGH RISK"

        return {
            "final_score": final_score,
            "final_verdict": verdict,
            "breakdown": breakdown
        }
