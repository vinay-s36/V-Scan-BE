import os
import warnings
from flask import Flask, request, abort, jsonify, send_from_directory
from flask_cors import CORS
from urllib.parse import urlparse
from scanner import WebVulnerabilityScanner
from dotenv import load_dotenv
from extensions import db
from models import Scan

warnings.filterwarnings("ignore", category=UserWarning)
app = Flask(__name__)
CORS(app)
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except ValueError:
        return False


@app.route('/reports/<path:filename>', methods=['GET'])
def download_report(filename):
    print(filename)
    try:
        safe_filename = os.path.basename(filename)
        file_path = os.path.join('scan_reports', safe_filename)

        if not file_path.startswith(os.path.join('scan_reports', '')):
            return abort(403, description="Forbidden access to file outside scan_reports")

        if not os.path.exists(file_path):
            return abort(404, description="File not found")

        return send_from_directory(
            directory="./scan_reports",
            path=safe_filename,
            as_attachment=True
        )
    except Exception as e:
        return str(e), 404


@app.route('/scans', methods=['GET'])
def get_scans():
    try:
        scans = Scan.query.all()
        scans_list = [
            {
                "id": scan.id,
                "target_url": scan.target_url,
                "status": scan.status,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "report": scan.report,
                "date": scan.created_at
            }
            for scan in scans
        ]
        return jsonify(scans_list), 200
    except Exception as e:
        return {"error": str(e)}, 500


@app.route('/scan', methods=['POST'])
def scan():
    scan = None
    try:
        data = request.get_json()
        if not data or 'target_url' not in data:
            return jsonify({"error": "Missing 'target_url' in request body"}), 400
        target_url = data['target_url']

        if not is_valid_url(target_url):
            return jsonify({"error": "Invalid URL format"}), 400

        scanner = WebVulnerabilityScanner(target_url)
        try:
            total_vulnerabilities = scanner.scan_website()
        except Exception as e:
            return jsonify({"error1": str(e)}), 500

        try:
            filename = scanner.generate_report()
        except Exception as e:
            return jsonify({"error2": str(e)}), 500

        scan = Scan(
            target_url=target_url,
            status='Completed',
            total_vulnerabilities=total_vulnerabilities,
            report=filename
        )
        db.session.add(scan)
        db.session.commit()

        return jsonify({"message": "Scanned successfully"}), 200

    except Exception as e:
        if scan:
            scan.status = 'Failed'
            db.session.commit()
        return jsonify({"error": str(e)}), 500


@app.route('/', methods=['GET'])
def home():
    return "Web vulnerability scanner"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
