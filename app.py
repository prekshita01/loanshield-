import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for

from database import db, ScanHistory, seed_nbfc_database
from analyzer import AppAnalyzer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure local SQLite database
if os.environ.get('VERCEL_ENV') or os.environ.get('VERCEL'):
    db_path = '/tmp/loanshield.db'
else:
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'loanshield.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db.init_app(app)

# Initialize Analyzer coordinator
# Load VirusTotal API Key from environment if available
vt_key = os.environ.get("VT_API_KEY", "")
analyzer = AppAnalyzer(vt_api_key=vt_key)

# Ensure tables are created and NBFC lists are seeded
with app.app_context():
    try:
        db.create_all()
        seed_nbfc_database()
        logger.info("Database initialized and seeded successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

@app.route('/')
def index():
    """Dashboard homepage displaying stats and scan triggers."""
    try:
        total_scans = ScanHistory.query.count()
        high_risk = ScanHistory.query.filter_by(final_verdict='HIGH RISK').count()
        suspicious = ScanHistory.query.filter_by(final_verdict='SUSPICIOUS').count()
        safe = ScanHistory.query.filter_by(final_verdict='SAFE').count()
        
        # Latest 5 scans
        recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(5).all()
        
        return render_template(
            'dashboard.html',
            total_scans=total_scans,
            high_risk=high_risk,
            suspicious=suspicious,
            safe=safe,
            recent_scans=recent_scans
        )
    except Exception as e:
        logger.error(f"Dashboard load error: {e}")
        return render_template(
            'dashboard.html',
            total_scans=0,
            high_risk=0,
            suspicious=0,
            safe=0,
            recent_scans=[]
        )

@app.route('/scan/<int:scan_id>')
def scan_detail(scan_id):
    """Scan details forensic audit report page."""
    scan = ScanHistory.query.get_or_404(scan_id)
    
    # Parse stored JSON structures
    try:
        details = json.loads(scan.details_json) if scan.details_json else {}
    except Exception:
        details = {}
        
    return render_template('scan.html', scan=scan, details=details)

@app.route('/history')
def history():
    """Tabular listing of past audit records."""
    verdict_filter = request.args.get('verdict', '').strip().upper()
    
    query = ScanHistory.query
    if verdict_filter in ['SAFE', 'SUSPICIOUS', 'HIGH_RISK']:
        # Map URL safe format HIGH_RISK to DB text 'HIGH RISK'
        db_verdict = verdict_filter.replace('_', ' ')
        query = query.filter_by(final_verdict=db_verdict)
        
    scans = query.order_by(ScanHistory.created_at.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/compliance')
def compliance():
    """Information portal on RBI digital lending guidelines."""
    return render_template('compliance.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    POST API to launch security analysis pipeline.
    Expects form input: 'query' (App Name, URL, or Package ID).
    """
    query = request.form.get('query', '').strip()
    if not query:
        return jsonify({"status": "error", "message": "Search target query cannot be empty."}), 400

    try:
        logger.info(f"Received scan request for query: {query}")
        
        # Execute the comprehensive check pipelines
        results = analyzer.run_analysis(query, db_session=db.session)
        
        app_info = results["app_info"]
        vt_res = results["vt_results"]
        osint_res = results["osint_results"]
        rbi_res = results["rbi_results"]
        risk_res = results["risk_results"]

        # Insert scan transaction in DB
        scan_record = ScanHistory(
            app_name=app_info["app_name"],
            package_name=app_info["package_name"],
            developer_name=app_info["developer_name"],
            developer_email=app_info["developer_email"],
            developer_website=app_info["developer_website"],
            installs=app_info["installs"],
            ratings=app_info["ratings"],
            privacy_policy_url=app_info["privacy_policy_url"],
            
            play_store_risk_score=risk_res["breakdown"]["dangerous_permissions"]["score"],
            compliance_score=rbi_res["compliance_score"],
            compliance_status=rbi_res["compliance_status"],
            threat_score=vt_res["threat_score"],
            url_reputation_score=osint_res["risk_score"],
            osint_score=osint_res["risk_score"],
            final_score=risk_res["final_score"],
            final_verdict=risk_res["final_verdict"],
            
            dangerous_permissions=json.dumps(app_info["permissions"]),
            details_json=json.dumps(results)
        )
        
        db.session.add(scan_record)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "scan_id": scan_record.id
        })

    except Exception as e:
        logger.error(f"API Scan Pipeline Error: {e}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": f"Scan failed due to backend engine error: {str(e)}"
        }), 500

if __name__ == '__main__':
    # Start web server on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
