import re
import time
import sqlite3
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

# SQLite database setup
def init_db():
    conn = sqlite3.connect('vuln_scanner.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target_url TEXT,
                  status TEXT,
                  start_time TEXT,
                  end_time TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  vulnerability TEXT,
                  severity TEXT,
                  url TEXT,
                  payload TEXT,
                  evidence TEXT,
                  FOREIGN KEY(scan_id) REFERENCES scans(id))''')
    conn.commit()
    conn.close()

init_db()

# Vulnerability payloads
PAYLOADS = {
    "SQLi": [
        "' OR '1'='1'--",
        "' OR SLEEP(5)--",
        "\" OR \"\"=\"",
        "' OR 1=1; DROP TABLE users--",
        "1; SELECT * FROM users",
        "admin'--"
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')"
    ]
}

# Vulnerability signatures
SIGNATURES = {
    "SQLi": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysqli_",
        r"Unclosed quotation mark",
        r"Syntax error.*SQL",
        r"ORA-[0-9]{5}",
        r"Microsoft OLE DB Provider for ODBC Drivers"
    ],
    "XSS": [
        r"<script>alert\('XSS'\)</script>",
        r"<img src=x onerror=alert\('XSS'\)>",
        r"<svg/onload=alert\('XSS'\)>"
    ]
}

SEVERITY_LEVELS = {
    "SQLi": "High",
    "XSS": "Medium",
    "CSRF": "Medium"
}

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnScanner/1.0"
        })
        self.scan_id = None
        self.results = []
    
    def start_scan(self):
        conn = sqlite3.connect('vuln_scanner.db')
        c = conn.cursor()
        c.execute("INSERT INTO scans (target_url, status, start_time) VALUES (?, ?, ?)",
                  (self.target_url, "Running", time.strftime("%Y-%m-%d %H:%M:%S")))
        self.scan_id = c.lastrowid
        conn.commit()
        conn.close()
        
        self.crawl_and_scan()
        return self.scan_id
    
    def crawl_and_scan(self):
        try:
            # Get base page and find forms
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Scan found forms
            for form in soup.find_all('form'):
                self.test_form(form)
            
            # Scan URL parameters
            self.test_url_parameters(response.url)
            
            # Update scan status
            self.update_scan_status("Completed")
        except Exception as e:
            self.log_finding("Scan Error", "Critical", self.target_url, "", str(e))
            self.update_scan_status("Failed")
    
    def test_form(self, form):
        try:
            form_details = self.get_form_details(form)
            for payload_type in ["SQLi", "XSS"]:
                for payload in PAYLOADS[payload_type]:
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden":
                            data[input_tag["name"]] = input_tag["value"]
                        elif input_tag["type"] != "submit":
                            data[input_tag["name"]] = payload
                    
                    url = form_details["action"] if form_details["action"] else self.target_url
                    if form_details["method"].lower() == "post":
                        response = self.session.post(url, data=data)
                    else:
                        response = self.session.get(url, params=data)
                    
                    self.check_response(payload_type, payload, response)
        except Exception as e:
            self.log_finding("Scan Error", "Critical", self.target_url, "", str(e))
    
    def test_url_parameters(self, url):
        try:
            parsed_url = requests.utils.urlparse(url)
            query_params = requests.utils.parse_qs(parsed_url.query)
            
            for param in query_params:
                for payload_type in ["SQLi", "XSS"]:
                    for payload in PAYLOADS[payload_type]:
                        modified_params = query_params.copy()
                        modified_params[param] = payload
                        
                        new_query = "&".join(
                            f"{k}={v[0]}" for k, v in modified_params.items()
                        )
                        target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        
                        response = self.session.get(target_url)
                        self.check_response(payload_type, payload, response)
        except Exception as e:
            self.log_finding("Scan Error", "Critical", url, "", str(e))
    
    def check_response(self, vuln_type, payload, response):
        # Check for reflected payloads
        if payload in response.text:
            self.log_finding(vuln_type, SEVERITY_LEVELS[vuln_type], 
                             response.url, payload, "Payload reflected in response")
            return
        
        # Check for signature matches
        for pattern in SIGNATURES[vuln_type]:
            if re.search(pattern, response.text, re.IGNORECASE):
                self.log_finding(vuln_type, SEVERITY_LEVELS[vuln_type], 
                                 response.url, payload, f"Signature match: {pattern}")
                return
        
        # Time-based SQLi detection
        if vuln_type == "SQLi" and "' OR SLEEP" in payload:
            if response.elapsed.total_seconds() >= 5:
                self.log_finding(vuln_type, SEVERITY_LEVELS[vuln_type], 
                                 response.url, payload, f"Time delay detected ({response.elapsed.total_seconds()}s)")
    
    def log_finding(self, vulnerability, severity, url, payload, evidence):
        self.results.append({
            "vulnerability": vulnerability,
            "severity": severity,
            "url": url,
            "payload": payload,
            "evidence": evidence
        })
        
        conn = sqlite3.connect('vuln_scanner.db')
        c = conn.cursor()
        c.execute("INSERT INTO findings (scan_id, vulnerability, severity, url, payload, evidence) VALUES (?, ?, ?, ?, ?, ?)",
                  (self.scan_id, vulnerability, severity, url, payload, evidence))
        conn.commit()
        conn.close()
    
    def update_scan_status(self, status):
        conn = sqlite3.connect('vuln_scanner.db')
        c = conn.cursor()
        c.execute("UPDATE scans SET status = ?, end_time = ? WHERE id = ?",
                  (status, time.strftime("%Y-%m-%d %H:%M:%S"), self.scan_id))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_form_details(form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_value
                })
        
        for select_tag in form.find_all("select"):
            select_name = select_tag.attrs.get("name")
            if select_name:
                inputs.append({
                    "type": "select",
                    "name": select_name,
                    "options": [
                        option.attrs.get("value") 
                        for option in select_tag.find_all("option")
                    ]
                })
        
        for textarea_tag in form.find_all("textarea"):
            textarea_name = textarea_tag.attrs.get("name")
            if textarea_name:
                inputs.append({
                    "type": "textarea",
                    "name": textarea_name,
                    "value": textarea_tag.text
                })
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

# Flask Routes
@app.route('/')
def index():
    conn = sqlite3.connect('vuln_scanner.db')
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")
    scans = c.fetchall()
    conn.close()
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('target_url')
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    scanner = VulnerabilityScanner(target_url)
    scan_id = scanner.start_scan()
    return redirect(url_for('scan_results', scan_id=scan_id))

@app.route('/scan/<int:scan_id>')
def scan_results(scan_id):
    conn = sqlite3.connect('vuln_scanner.db')
    c = conn.cursor()
    
    # Get scan info
    c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = c.fetchone()
    
    # Get findings
    c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = c.fetchall()
    
    conn.close()
    
    if not scan:
        return "Scan not found", 404
    
    return render_template('results.html', scan=scan, findings=findings)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({"error": "Missing target_url"}), 400
    
    scanner = VulnerabilityScanner(target_url)
    scan_id = scanner.start_scan()
    return jsonify({"scan_id": scan_id, "status": "started"})

@app.route('/api/scan/<int:scan_id>')
def api_scan_results(scan_id):
    conn = sqlite3.connect('vuln_scanner.db')
    c = conn.cursor()
    
    # Get scan info
    c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = c.fetchone()
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Get findings
    c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings = c.fetchall()
    
    conn.close()
    
    # Format response
    scan_data = {
        "id": scan[0],
        "target_url": scan[1],
        "status": scan[2],
        "start_time": scan[3],
        "end_time": scan[4]
    }
    
    findings_data = []
    for finding in findings:
        findings_data.append({
            "vulnerability": finding[2],
            "severity": finding[3],
            "url": finding[4],
            "payload": finding[5],
            "evidence": finding[6]
        })
    
    return jsonify({"scan": scan_data, "findings": findings_data})

if __name__ == '__main__':
    app.run(debug=True)