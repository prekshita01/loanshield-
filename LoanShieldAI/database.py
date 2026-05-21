import os
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(255), nullable=False)
    package_name = db.Column(db.String(255), nullable=True)
    developer_name = db.Column(db.String(255), nullable=True)
    developer_email = db.Column(db.String(255), nullable=True)
    developer_website = db.Column(db.String(512), nullable=True)
    installs = db.Column(db.String(50), nullable=True)
    ratings = db.Column(db.Float, default=0.0)
    privacy_policy_url = db.Column(db.String(1024), nullable=True)
    
    # Scores (0-100)
    play_store_risk_score = db.Column(db.Integer, default=0)
    compliance_score = db.Column(db.Integer, default=0)
    compliance_status = db.Column(db.String(50), default='PENDING') # PASS, WARNING, FAIL
    threat_score = db.Column(db.Integer, default=0)
    url_reputation_score = db.Column(db.Integer, default=0)
    osint_score = db.Column(db.Integer, default=0)
    final_score = db.Column(db.Integer, default=0)
    final_verdict = db.Column(db.String(50), default='UNKNOWN') # SAFE, SUSPICIOUS, HIGH RISK
    
    # Detailed metadata stored as text (JSON encoded)
    dangerous_permissions = db.Column(db.Text, default='[]')
    details_json = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_details(self):
        try:
            return json.loads(self.details_json) if self.details_json else {}
        except Exception:
            return {}

    def get_permissions(self):
        try:
            return json.loads(self.dangerous_permissions) if self.dangerous_permissions else []
        except Exception:
            return []

class NBFCList(db.Model):
    __tablename__ = 'nbfc_list'
    
    id = db.Column(db.Integer, primary_key=True)
    nbfc_name = db.Column(db.String(255), nullable=False, unique=True)
    website = db.Column(db.String(512), nullable=True)
    license_number = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), default='ACTIVE')

def seed_nbfc_database():
    """Seed the database with well-known RBI-registered NBFCs and fintech partners."""
    default_nbfcs = [
        {"nbfc_name": "Bajaj Finance Limited", "website": "bajajfinserv.in", "license_number": "N-13.00403"},
        {"nbfc_name": "DMI Finance Private Limited", "website": "dmifinance.in", "license_number": "N-14.03126"},
        {"nbfc_name": "Aditya Birla Finance Limited", "website": "adityabirlafinance.com", "license_number": "N-16.00156"},
        {"nbfc_name": "Tata Capital Financial Services Limited", "website": "tatacapital.com", "license_number": "N-13.01872"},
        {"nbfc_name": "L&T Finance Limited", "website": "ltfs.com", "license_number": "N-13.01868"},
        {"nbfc_name": "Muthoot Fincorp Limited", "website": "muthootfincorp.com", "license_number": "N-16.00170"},
        {"nbfc_name": "InCred Financial Services Limited", "website": "incred.com", "license_number": "N-13.02197"},
        {"nbfc_name": "Krazybee Services Private Limited", "website": "krazybee.com", "license_number": "N-13.02234"},
        {"nbfc_name": "Kisetsu Saison Finance (India) Private Limited", "website": "creditsaison.in", "license_number": "N-02.00288"},
        {"nbfc_name": "Northern Arc Capital Limited", "website": "northernarc.com", "license_number": "N-07.00769"},
        {"nbfc_name": "Earlysalary Services Private Limited (Fibe)", "website": "fibe.in", "license_number": "N-13.02245"},
        {"nbfc_name": "PayU Finance India Private Limited", "website": "payufin.in", "license_number": "N-13.02283"},
        {"nbfc_name": "IIFL Finance Limited", "website": "iifl.com", "license_number": "N-13.01804"},
        {"nbfc_name": "Manappuram Finance Limited", "website": "manappuram.com", "license_number": "N-16.00029"},
        {"nbfc_name": "Navi Finserv Limited", "website": "navi.com", "license_number": "N-13.02111"}
    ]
    
    for nbfc in default_nbfcs:
        exists = NBFCList.query.filter_by(nbfc_name=nbfc["nbfc_name"]).first()
        if not exists:
            db.session.add(NBFCList(**nbfc))
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error seeding NBFC list: {e}")
