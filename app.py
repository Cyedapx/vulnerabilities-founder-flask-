from flask import Flask, render_template, request
import requests

app = Flask(__name__)

common_vulnerabilities = [
"sql_injection", "csrf ",
"xss", "Command Injection",
"Security Misconfiguration",
"Broken Authentication and Session Management",
"Insecure Deserialization",
"Sensitive Data Exposure",
"XML External Entity (XXE) Attacks",
"Insecure Direct Object References",
"Security Bypass",
"File Upload Vulnerabilities",
"Server-Side Request Forgery (SSRF)",
"Unvalidated Redirects and Forwards",
"Remote Code Execution (RCE)"]

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    urls_to_scan = request.form.get("urls").split(",")
    vulnerabilities_found = []

    for url in urls_to_scan:
        vulnerabilities = check_for_vulnerabilities(url.strip())
        vulnerabilities_found.extend(vulnerabilities)

    return render_template("results.html", vulnerabilities=vulnerabilities_found)

def check_for_vulnerabilities(url):
    vulnerabilities = []
    response = requests.get(url)
    
    if response.status_code == 200:
        page_content = response.text

        for vulnerability in common_vulnerabilities:
            if vulnerability in page_content:
                vulnerabilities.append(f"Vulnerability '{vulnerability}' found on {url}")

    return vulnerabilities

if __name__ == "__main__":
    app.run(debug=True)
