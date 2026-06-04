# Secure Coding Review & Vulnerability Audit Report

## 📌 Project Overview
This repository contains the comprehensive deliverables for **Task 3: Secure Coding Review** as part of my Cybersecurity Internship at **CodeAlpha**. The core objective of this project is to perform a meticulous security audit on a standard web application backend (written in Python/Flask), identify critical security flaws based on the **OWASP Top 10 Framework**, map their operational risks, and provide production-ready secure remediations.

---

## 🛠️ Methodology & Scope
The assessment was executed utilizing a hybrid security audit approach to maximize coverage and accuracy:
1. **Manual Source Code Inspection (MCI):** Line-by-line manual code verification targeting data flow paths, parameter handling, context isolation, and backend database entry points.
2. **Static Application Security Testing (SAST):** Automated vulnerability tracking and linting referenced against industry-standard security checkers such as **Bandit** (for Python native AST testing) and **SonarQube** code smell matrices.

---

## 🔍 Vulnerability Mapping & Remediation Matrix

### Finding 1: SQL Injection (SQLi) via Dynamic Query Concatenation
* **Vulnerability Class:** OWASP Top 10:2021 – A03: Injection
* **CVSS v3.1 Score:** 9.8 (Critical)
* **Risk Description:** The application directly binds unvalidated user inputs from query string parameters into the operational database command layer via string interpolation. An attacker can manipulate inputs using SQL payload structures (e.g., `' OR '1'='1`) to completely bypass authorization, extract systemic database tables, or manipulate internal records.

#### ❌ Vulnerable Implementation (Unsafe Code)
```python
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/v1/user/profile', methods=['GET'])
def get_user_profile():
    # HIGH RISK: Direct acquisition of unsanitized string parameter
    username = request.args.get('username')
    
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    
    # CRITICAL VULNERABILITY: Raw string formatting allows raw SQL injection
    query = f"SELECT user_id, email, role FROM users WHERE username = '{username}'"
    cursor.execute(query)from flask import Flask, request, jsonify
import sqlite3
import re

app = Flask(__name__)

@app.route('/api/v1/user/profile', methods=['GET'])
def get_user_profile():
    username = request.args.get('username', '')
    
    # DEFENSE-IN-DEPTH: Input validation using strict regex pattern matching
    if not re.match("^[a-zA-Z0-9_]{3,30}$", username):
        return jsonify({"error": "Invalid input formatting detected"}), 400
        
    conn = sqlite3.connect('app_database.db')
    cursor = conn.cursor()
    
    # REMEDIATION: Parameterized query (Prepared Statements) separates code logic from user data
    query = "SELECT user_id, email, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    user_data = cursor.fetchone()
    if not user_data:
        return jsonify({"error": "User not found"}), 404
        
    return jsonify({
        "user_id": user_data[0],
        "email": user_data[1],
        "role": user_data[2]
    }), 200
    Finding 2: Hardcoded Secrets & Sensitive Key Exposure
Vulnerability Class: OWASP Top 10:2021 – A05: Security Misconfiguration

CVSS v3.1 Score: 8.9 (High)

Risk Description: Sensitive production JSON Web Token (JWT) cryptographic keys and third-party API payment credentials are saved directly within the source code configuration layer as plaintext strings. If this code is pushed into a shared repository, the cryptographic tokens and infrastructure are permanently exposed to threat actors.
❌ Vulnerable Implementation (Unsafe Code)
import os
import jwt

# CRITICAL VULNERABILITY: Hardcoded production secret and payment gateway key
JWT_SECRET_KEY = "PRODUCTION_SUPER_SECRET_KEY_DONT_SHARE_123"
STRIPE_API_TOKEN = "sk_live_51Nx...v82K" 

def generate_auth_token(user_id):
    # Plaintext token sign manipulation without access control rotation
    payload = {'sub': user_id, 'scope': 'internal_api'}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    ✅ Remediated Implementation (Secure Code)
    import os
import jwt
from dotenv import load_dotenv

# REMEDIATION: Load runtime states and configurations securely from isolated environment variables
load_dotenv()

# Cryptographic recovery fallbacks if environment parsing breaks safely
JWT_SECRET_KEY = os.getenv('APP_JWT_SECRET_KEY')
STRIPE_API_TOKEN = os.getenv('STRIPE_PRODUCTION_API_TOKEN')

if not JWT_SECRET_KEY or not STRIPE_API_TOKEN:
    raise RuntimeError("Critical environment configuration missing. Halt process initialization.")

def generate_auth_token(user_id):
    payload = {'sub': user_id, 'scope': 'internal_api'}
    # Standard secure cryptographic token signing processing
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    
    🧑‍💻 Prepared By:
Name: Mohammad Abdullah

Role: Cybersecurity Intern (CodeAlpha)

Credentials: CEH Certified / Software Quality Assurance (SQA) Engineer
    
