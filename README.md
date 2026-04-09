# SOC Lab: Elastic Security + AWS Honeypot + Active Directory Endpoints

This project is a full end‑to‑end SOC lab designed to simulate real attacker behavior against a public‑facing HR web portal (honeypot) hosted in AWS. Telemetry from the honeypot and multiple Active Directory–joined Windows endpoints is shipped to Elastic Security for detection, alerting, and investigation.

The lab demonstrates:

- Building an AWS VPC and EC2 infrastructure  
- Creating an AD domain with multiple enterprise endpoints  
- Deploying Elastic Agent + Elastic Defend  
- Deploying a Python honeypot with geo‑IP enrichment  
- Shipping honeypot + endpoint logs to Elastic Cloud  
- Triggering and investigating detection rules  
- Analyzing suspicious process chains  
- Using geo‑enriched honeypot data  

---

# 2. Architecture Diagram



<img width="816" height="1163" alt="Screenshot 2026-04-09 161028" src="https://github.com/user-attachments/assets/71432b66-3696-4dce-a4a9-349e73fb1b3a" />




---

# 3. AWS Setup (VPC + EC2 Infrastructure)

## 3.1 Create the VPC

- Create a **VPC** (10.0.0.0/16)  
- Create a **public subnet** (10.0.1.0/24)  
- Create + attach an **Internet Gateway**  
- Create a **route table** with `0.0.0.0/0 → IGW`  
- Associate the route table with the public subnet  

## 3.2 Launch EC2 Instances

You will create:

- **1 Domain Controller (Windows Server)**  
- **Multiple Windows endpoints**  
- **1 Honeypot EC2 instance (Windows Server)**  

All machines must be in the **same VPC**, but the honeypot will use a **separate Security Group**.

---

# 4. Active Directory Lab

## 4.1 Domain Controller Setup

- Install **AD DS**, **DNS**, **File Services**  
- Promote to domain controller (`lab.local`)  



<img width="1240" height="1135" alt="Screenshot 2026-04-09 124326" src="https://github.com/user-attachments/assets/af474e53-9d5f-4e8c-bd4d-4c1b12816491" />



## 4.2 Join Windows Endpoints to AD

Endpoints:

- CORP-BILLING  
- CORP-DEVOPS  
- CORP-FINANCE01  
- CORP-ITADMIN  





<img width="932" height="613" alt="Screenshot 2026-04-09 124349" src="https://github.com/user-attachments/assets/8cdc30ea-07ad-4116-b6f7-6e923017f7f2" />



---

# 5. Elastic Cloud + Fleet + Agent Policy

## 5.1 Deploy Elastic Cloud

- Create deployment  
- Copy **Cloud ID** + **Enrollment Token**  

## 5.2 Create Agent Policy

Add integrations:

- Elastic Agent  
- Elastic Defend  
- Windows  
- System  
- Custom Logs (for honeypot)  


<img width="1368" height="711" alt="Screenshot 2026-04-09 124221" src="https://github.com/user-attachments/assets/6bac0e68-9654-4cff-a90d-d98804a83597" />



---

# 6. Install Elastic Agent on All Hosts

Install Elastic Agent on:

- Domain Controller  
- All AD‑joined Windows endpoints  
- **Honeypot EC2 instance** (this is where the Python listener will run)


<img width="1737" height="569" alt="Screenshot 2026-04-09 164933" src="https://github.com/user-attachments/assets/6578f024-ac59-4ec9-b91e-4d2102e4103f" />



---

# 7. Honeypot Deployment (AFTER Agent Install)

This section covers **creating the honeypot VM**, **security group**, **Python setup**, and **running the honeypot engine**.

## 7.1 Create Honeypot EC2 Instance

- Launch **Windows Server**  
- Place it in the **public subnet**  
- Assign a **public IPv4 address**  
- DO NOT join it to the domain  

## 7.2 Create a Separate Security Group (NSG)

Create a new SG named: **Honeypot-SG**

Allow inbound:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 80   | TCP      | 0.0.0.0/0 | HTTP honeypot |
| 443  | TCP      | 0.0.0.0/0 | HTTPS honeypot |
| 3389 | TCP      | Your IP | RDP admin access |

Attach this SG to the honeypot EC2 instance.

## 7.3 Install Python + Dependencies

On the honeypot EC2:

```
winget install Python.Python.3
pip install flask waitress geoip2
```

## 7.4 Deploy Honeypot Code

### Creating the Fake File Folder and Running the Script

The honeypot engine and the fake corporate documents live in different folders.  
The honeypot engine stays in its own directory, but the fake files must be placed in the **public** folder that the web portal serves.

Create the public folder (if it doesn't already exist):

```
C:\HoneypotEngine\public\
```

Run the fake‑file script on the honeypot VM.  
The script will automatically create the folder if needed and then generate all the decoy HR/Finance/IT documents inside:

```
C:\HoneypotEngine\public\
```

### Fake File Generation Script

```powershell
# Create fake corporate files that match the HR Portal screenshot
$path = "C:\HoneypotEngine\public\"
New-Item -ItemType Directory -Force -Path $path | Out-Null

$files = @(
    "Benefits_Overview.docx",
    "Budget_Forecast_2024.xlsx",
    "Compliance_Training_Overview.docx",
    "Confidential_Project_Plan.pdf",
    "Employee_Handbook_2024.pdf",
    "Expense_Report_Template.xlsx",
    "HR_Policies_2024.docx",
    "IT_Security_Policy.pdf",
    "Incident_Report_Form.pdf",
    "Internal_Audit_Notes.pdf",
    "Meeting_Minutes_Template.docx",
    "NewHire_Onboarding_Checklist.docx",
    "OrgChart_2024.png",
    "Password_Reset_Guide.pdf",
    "Payroll_Q1_2024.xlsx",
    "Performance_Review_Form.docx",
    "Server_Access_Request_Form.docx",
    "Training_Schedule_2024.xlsx",
    "Travel_Reimbursement_Form.pdf",
    "VPN_Instructions.docx",
    "index.html"
)

foreach ($file in $files) {
    $full = Join-Path $path $file
    "This is a placeholder decoy file for honeypot interaction." | Out-File $full -Encoding utf8
}
```

This is the folder the HR Employee Portal reads from when showing the document list to attackers.



Create folder:

```
C:\HoneypotEngine\
```

Place your honeypot.py script here:

```
C:\HoneypotEngine\honeypot.py
```

Paste your full honeypot code:

```python
import os
import json
import uuid
import re
import html
import datetime

from flask import Flask, request, send_file, Response
from waitress import serve

try:
    from geoip2.database import Reader as GeoReader
except ImportError:
    GeoReader = None

# ============================
# CONFIG PATHS
# ============================
PUBLIC_PATH = r"C:\Honeypot"
LOG_PATH = r"C:\HoneypotEngine\logs\honeypot.log"
GEO_DB_PATH = r"C:\HoneypotEngine\GeoLite2-City.mmdb"

os.makedirs(PUBLIC_PATH, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

geo_reader = None
if GeoReader is not None and os.path.exists(GEO_DB_PATH):
    try:
        geo_reader = GeoReader(GEO_DB_PATH)
    except Exception:
        geo_reader = None

app = Flask(__name__)

# ============================
# GEOLOCATION LOOKUP FUNCTION
# ============================
def get_geolocation(ip: str) -> dict:
    if not geo_reader:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": 0,
            "lon": 0,
        }
    try:
        city = geo_reader.city(ip)
        return {
            "country": city.country.name or "Unknown",
            "city": city.city.name or "Unknown",
            "lat": city.location.latitude or 0,
            "lon": city.location.longitude or 0,
        }
    except Exception:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": 0,
            "lon": 0,
        }

# ============================
# BOT / SCANNER DETECTION
# ============================
BOT_REGEX = re.compile(r"curl|python|wget|bot|scanner|nmap", re.IGNORECASE)
SCANNER_PATH_REGEX = re.compile(r"admin|wp-login|phpmyadmin|shell|cmd|\.env|\.git", re.IGNORECASE)

def get_bot_heuristic(user_agent: str, path: str) -> str:
    ua = user_agent or ""
    p = path or ""
    if BOT_REGEX.search(ua):
        return "bot"
    if SCANNER_PATH_REGEX.search(p):
        return "scanner"
    return "human"

# ============================
# SESSION ID GENERATOR
# ============================
def new_session_id() -> str:
    return str(uuid.uuid4())

# ============================
# CONTENT TYPE HELPER
# ============================
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

def get_content_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return CONTENT_TYPES.get(ext, "application/octet-stream")

# ============================
# SAFE FILE PATH RESOLUTION
# ============================
def resolve_safe_file_path(base_path: str, requested_name: str):
    try:
        candidate = os.path.join(base_path, requested_name)
        full_base = os.path.realpath(base_path)
        full_candidate = os.path.realpath(candidate)
        if os.path.commonprefix([full_base, full_candidate]) == full_base:
            return full_candidate
        return None
    except Exception:
        return None

# ============================
# STRUCTURED JSON LOGGING
# ============================
def write_honeypot_log(ip, port, action, username, password, path, method, ua):
    geo = get_geolocation(ip)
    session = new_session_id()
    bot_type = get_bot_heuristic(ua, path)

    log_object = {
        "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "session.id": session,
        "source.ip": ip,
        "source.port": port,
        "event.action": action,
        "url.path": path,
        "http.method": method,
        "user.name": username or "",
        "user.password": password or "",
        "user_agent.original": ua or "",
        "source.geo.country_name": geo["country"],
        "source.geo.city_name": geo["city"],
        "source.geo.location.lat": geo["lat"],
        "source.geo.location.lon": geo["lon"],
        "attacker.type": bot_type,
    }

    line = json.dumps(log_object, separators=(",", ":"))
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ============================
# PORTAL HTML TEMPLATE
# ============================
PORTAL_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HR Employee Portal</title>
    <style>
        body { font-family: Arial; background: #f3f5f7; }
        .container { max-width: 1150px; margin: 30px auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.12); padding: 30px; }
        .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 1px solid #e3e7eb; padding-bottom: 12px; }
        .brand { font-size: 24px; font-weight: bold; color: #1f4e79; }
        .sub { color: #5a6570; font-size: 14px; }
        .notice { background: #fff4db; border: 1px solid #f0d58c; color: #6e5800; padding: 12px; border-radius: 6px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 340px 1fr; gap: 24px; }
        .card { background: #fafafa; border: 1px solid #dcdcdc; border-radius: 8px; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; }
        th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e2e2; }
        th { background: #eef3f8; color: #234; }
        a { color: #1f4e79; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .footer { margin-top: 24px; color: #666; font-size: 12px; border-top: 1px solid #e3e7eb; padding-top: 14px; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 6px 0 12px 0; box-sizing: border-box; }
        input[type=submit] { padding: 8px 16px; background: #1f4e79; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        input[type=submit]:hover { background: #163857; }
    </style>
</head>
<body>
    <div class="container">
        <div class="topbar">
            <div>
                <div class="brand">HR Employee Portal</div>
                <div class="sub">Corporate Intranet Resources</div>
            </div>
        </div>

        {notice_html}

        <div class="grid">
            <div class="card">
                <h2>Employee Sign-In</h2>
                <form method="POST" action="/login">
                    <label>Employee ID</label>
                    <input type="text" name="user">
                    <label>Password</label>
                    <input type="password" name="pass">
                    <input type="submit" value="Login">
                </form>
            </div>

            <div class="card">
                <h2>Shared Documents</h2>
                <table>
                    <thead><tr><th>Name</th><th>Type</th><th>Size</th></tr></thead>
                    <tbody>{file_table}</tbody>
                </table>
            </div>
        </div>

        <div class="footer">Internal access only. Unauthorized use is prohibited.</div>
    </div>
</body>
</html>
"""

# ============================
# PORTAL HTML GENERATOR
# ============================
def get_portal_html(base_path: str, message: str = "") -> str:
    try:
        files = [f for f in os.listdir(base_path) if os.path.isfile(os.path.join(base_path, f))]
        files.sort()
    except FileNotFoundError:
        files = []

    rows = []
    for name in files:
        full_path = os.path.join(base_path, name)
        safe_name = html.escape(name)
        href_name = html.escape(name)
        ext = os.path.splitext(name)[1]
        if not ext:
            ext_display = "FILE"
        else:
            ext_display = ext.lstrip(".").upper()
        size_kb = round(os.path.getsize(full_path) / 1024.0, 2)
        rows.append(
            f"<tr><td><a href='/files/{href_name}'>{safe_name}</a></td>"
            f"<td>{ext_display}</td><td>{size_kb} KB</td></tr>"
        )

    if not rows:
        rows = ["<tr><td colspan='3'>No documents available.</td></tr>"]

    file_table = "\n".join(rows)

    notice_html = ""
    if message and message.strip():
        safe_message = html.escape(message)
        notice_html = f"<div class='notice'>{safe_message}</div>"

    # Avoid .format() so CSS braces never break things
    html_body = PORTAL_TEMPLATE.replace("{notice_html}", notice_html).replace("{file_table}", file_table)
    return html_body

# ============================
# ROUTES
# ============================
def client_ip_port():
    ip = request.remote_addr or "0.0.0.0"
    port = 0
    return ip, port

@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
def main_portal():
    ip, port = client_ip_port()
    ua = request.headers.get("User-Agent", "")
    raw_path = request.path

    html_body = get_portal_html(PUBLIC_PATH)
    write_honeypot_log(
        ip=ip,
        port=port,
        action="page_view",
        username="",
        password="",
        path=raw_path,
        method="GET",
        ua=ua,
    )
    return Response(html_body, status=200, mimetype="text/html; charset=utf-8")

@app.route("/login", methods=["POST"])
def login():
    ip, port = client_ip_port()
    ua = request.headers.get("User-Agent", "")
    raw_path = "/login"

    username = request.form.get("user", "")
    password = request.form.get("pass", "")

    write_honeypot_log(
        ip=ip,
        port=port,
        action="login_attempt",
        username=username,
        password=password,
        path=raw_path,
        method="POST",
        ua=ua,
    )

    html_body = get_portal_html(PUBLIC_PATH, message="Invalid Employee ID or Password.")
    return Response(html_body, status=200, mimetype="text/html; charset=utf-8")

@app.route("/files/<path:requested_name>", methods=["GET"])
def serve_file(requested_name):
    ip, port = client_ip_port()
    ua = request.headers.get("User-Agent", "")
    raw_path = f"/files/{requested_name}"

    if not requested_name.strip():
        html_body = get_portal_html(PUBLIC_PATH, message="Requested resource was not found.")
        write_honeypot_log(
            ip=ip,
            port=port,
            action="not_found",
            username="",
            password="",
            path=raw_path,
            method="GET",
            ua=ua,
        )
        return Response(html_body, status=404, mimetype="text/html; charset=utf-8")

    file_path = resolve_safe_file_path(PUBLIC_PATH, requested_name)
    if file_path and os.path.isfile(file_path):
        write_honeypot_log(
            ip=ip,
            port=port,
            action="file_access",
            username="",
            password="",
            path=raw_path,
            method="GET",
            ua=ua,
        )
        return send_file(file_path, mimetype=get_content_type(file_path), as_attachment=False)

    html_body = get_portal_html(PUBLIC_PATH, message="Requested resource was not found.")
    write_honeypot_log(
        ip=ip,
        port=port,
        action="not_found",
        username="",
        password="",
        path=raw_path,
        method="GET",
        ua=ua,
    )
    return Response(html_body, status=404, mimetype="text/html; charset=utf-8")

@app.route("/<path:raw_path>", methods=["GET"])
def fallback_files(raw_path):
    ip, port = client_ip_port()
    ua = request.headers.get("User-Agent", "")
    path_str = "/" + raw_path.lstrip("/")

    trimmed = raw_path.strip("/")
    if trimmed:
        fallback_path = resolve_safe_file_path(PUBLIC_PATH, trimmed)
        if fallback_path and os.path.isfile(fallback_path):
            write_honeypot_log(
                ip=ip,
                port=port,
                action="file_access",
                username="",
                password="",
                path=path_str,
                method="GET",
                ua=ua,
            )
            return send_file(fallback_path, mimetype=get_content_type(fallback_path), as_attachment=False)

    html_body = get_portal_html(PUBLIC_PATH, message="Requested resource was not found.")
    write_honeypot_log(
        ip=ip,
        port=port,
        action="not_found",
        username="",
        password="",
        path=path_str,
        method="GET",
        ua=ua,
    )
    return Response(html_body, status=404, mimetype="text/html; charset=utf-8")

# ============================
# ENTRY POINT
# ============================
if __name__ == "__main__":
    print("Corporate-style honeypot running on port 80...")
    print("Main page: http://<server-ip>/")
    serve(app, host="0.0.0.0", port=80)

```

## 7.5 Run the Honeypot

```
py C:\HoneypotEngine\honeypot.py
```

You should see:

```
Corporate-style honeypot running on port 80...
Main page: http://<server-ip>/
```

## 7.6 Verify Honeypot Frontend



<img width="2173" height="1480" alt="Screenshot 2026-04-09 124138" src="https://github.com/user-attachments/assets/cfe53b1d-c120-4e44-8ee0-cc0398bc2c40" />


---

# 8. Honeypot Telemetry + Geo Maps

## 8.1 Discover View (Honeypot Logs)



<img width="2410" height="1004" alt="Screenshot 2026-04-09 170937" src="https://github.com/user-attachments/assets/5c86a1e4-4aed-4e8b-9e03-e64dd2eb8992" />





## 8.2 Geo Maps

US-Map
<img width="1814" height="1150" alt="Screenshot 2026-04-09 155413" src="https://github.com/user-attachments/assets/56e4a02c-a995-4f5c-b281-7b72b5a75525" />

EU-Map
<img width="1823" height="1152" alt="Screenshot 2026-04-09 155454" src="https://github.com/user-attachments/assets/a608bbe7-67e4-4ea1-8090-a90648ce55cb" />



# 9. Detection Rules

Elastic Security rules used:

- Honeypot – Public IP Access Detected  
- Suspicious Parent Chain: CMD → PowerShell  
- Suspicious Binary Masquerading + Unusual Parent  
- Suspicious Process Chain  


<img width="2394" height="1311" alt="Screenshot 2026-04-09 132711" src="https://github.com/user-attachments/assets/49cd56b2-faac-4e8f-9227-50bc529b62c4" />



---

# 10. Suspicious Process Chain Lab

This lab simulates a suspicious process chain using a harmless PowerShell script.

## 10.1 Test Script (Notepad → PowerShell → Stop‑Process)

```
$np = Start-Process notepad.exe -PassThru
Start-Sleep -Seconds 2
Start-Process powershell.exe -ArgumentList "-NoLogo -NoProfile -Command `"Get-Process | Out-Null`"" -WindowStyle Hidden
Start-Sleep -Seconds 2
Stop-Process -Id $np.Id -Force
```

## 10.2 Why This Is Suspicious

- Notepad should usally **never** spawn PowerShell  
- Attackers use LOLBins to evade detection  
- Elastic Defend flags this as:
  - Execution  
  - Defense Evasion  
  - Masquerading  
  - Potential lateral movement  



# 11. Investigating the Alert

## 11.1 Alerts Summary


<img width="696" height="569" alt="Screenshot 2026-04-09 155922" src="https://github.com/user-attachments/assets/50489375-61d2-4066-9a2e-f227ec61d5c9" />


## 11.2 Command Line Details


<img width="605" height="1145" alt="Screenshot 2026-04-09 155946" src="https://github.com/user-attachments/assets/479f3209-05f8-464b-b78d-f43d56b85552" />



## 11.3 User Context


<img width="594" height="905" alt="Screenshot 2026-04-09 155956" src="https://github.com/user-attachments/assets/5a4c9cc9-2774-4b56-91a4-932920bb6dc3" />



## 11.4 Host Context


<img width="614" height="625" alt="Screenshot 2026-04-09 160008" src="https://github.com/user-attachments/assets/5c59fc9f-86d4-4b8a-a7c1-299ef31445c4" />



---



# 12. What This Lab Demonstrates

By completing this project, you achieve:

- A public AWS honeypot  
- A full AD enterprise environment  
- Elastic Agent + Defend on all hosts  
- Geo‑enriched honeypot telemetry  
- Custom + prebuilt detection rules  
- Realistic SOC investigation workflows  
- Full alert → process → user → host → timeline correlation  

---

# 13. Future Enhancements

- Sigma rules  
- Add Linux endpoints  
- Add Email and phishing simulation  
- Add automated host isolation workflows  

---

# 14. Credits

Created as a hands‑on SOC learning environment using:

- AWS  
- Elastic Security  
- Windows Server + AD  
- Python Honeypot



## Troubleshooting Guide

### EC2 Connectivity Issues
If your EC2 instances cannot talk to each other or the honeypot does not load, verify the Security Groups:

- Ensure each instance allows inbound traffic from the other instances’ Security Groups.
- Allow RDP (3389) only from your public IP.
- Ensure the honeypot instance allows inbound HTTP (80) and HTTPS (443) from 0.0.0.0/0.

### Honeypot Not Loading in Browser
If the HR Portal does not load:

- Confirm the honeypot script is running with no errors.
- Make sure the Windows Firewall allows inbound port 80.
- Use this PowerShell command to allow port 80:

```powershell
New-NetFirewallRule -DisplayName "Honeypot HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
```

### Elastic Agent Not Showing in Fleet
If an agent is missing or offline:

- Confirm the VM has internet access.
- Re-run the Elastic Agent install command with the correct enrollment token.
- Ensure no local firewall is blocking outbound traffic on ports 443 or 8220.

### Honeypot Files Not Appearing in the HR Portal
If the Shared Documents list is empty:

- Make sure the fake-file script was run on the honeypot VM.
- Verify the files exist in:

```
C:\HoneypotEngine\public\
```

- Restart the honeypot script if needed.

### AD Endpoints Not Sending Logs
If domain-joined machines show no telemetry:

- Ensure Elastic Agent is installed with the correct policy.
- Confirm the Windows Firewall allows outbound HTTPS.
- Restart the Elastic Agent service:

```powershell
Restart-Service elastic-agent
```

### GeoIP Not Showing in Elastic
If the map is empty:

- Ensure the honeypot is receiving real external traffic.
- Confirm the honeypot logs include the client IP field.
- Verify the ingest pipeline is enabled in your Elastic policy.

