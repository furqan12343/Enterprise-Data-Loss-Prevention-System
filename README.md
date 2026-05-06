# Enterprise Data Loss Prevention (DLP) System

## 1. Overview
The **Hash-Based Data Loss Prevention (DLP)** system is a web-based cybersecurity tool designed to prevent the unauthorized exfiltration of sensitive organizational data. Instead of keeping plain-text copies of sensitive files, the system utilizes advanced cryptographic hashing to fingerprint secure data. The system monitors outbound communications (like file uploads and emails) in real-time, blocking any activity that attempts to leak restricted information.

---

## 2. Core Architecture
The system is built using an MVC-style pattern with Python Flask serving as the backend and Bootstrap 5 handling the frontend layout.

### Technology Stack
* **Language:** Python
* **Web Framework:** Flask
* **Database:** SQLite (Unified Database Architecture)
* **Frontend:** HTML5, Bootstrap 5 CSS, Jinja2 Templating
* **Cryptographic Algorithms:** `SHA3-256` (Exact Match) and `SimHash` (Fuzzy Match)

### Database Schemas
The application utilizes two separate database files to maintain a strict boundary between authentication and logging.

1. **`user_pass_cred.db` / `admin_user_pass.db`**
   - Handles robust user identity management. Stores usernames and SHA-256 hashed login passwords.
   - Distinct databases ensure normal users and administrators are kept strictly separate.

2. **`database.db`** (The Master DLP Database)
   - **`sensitive_hashes` Table:** The brain of the system. Contains three key columns: `data_name`, `hash_value` (Exact SHA3 hash), and `fuzzy_hash_value` (64-bit Locality-Sensitive Hash).
   - **`logs` Table:** An immutable ledger tracking all simulation and email attempts, storing whether the transaction was `Allowed` or `Blocked`.

---

## 3. The Detection Engine (`dlp_core.py`)
At the heart of the system lies a dual-tier detection engine designed to catch both blatant data theft and obfuscated leaks.

### Tier 1: Exact Cryptographic Match
* **Algorithm:** `SHA3-256`
* **Mechanism:** When text or a file is registered, a one-way mathematical fingerprint is generated. If a user attempts to send an exact, byte-for-byte replica of a registered file, the SHA3-256 hash immediately matches, and the system blocks the transfer.

### Tier 2: Fuzzy Logic Match (Context-Triggered Piecewise Hashing)
* **Algorithm:** `SimHash`
* **Mechanism:** An attacker might try to bypass Tier 1 logic by changing a single word in a document. To prevent this, the system calculates a Locality-Sensitive Hash (LSH). The system checks the *Hamming Distance* between the incoming data's SimHash and the stored SimHashes. 
* **Threshold:** If the incoming data retains **70% or higher similarity** to a registered file (a Hamming Distance of ≤ 19 bits across the 64-bit fingerprint), the system intelligently flags it as a modified duplicate and blocks the transfer.

---

## 4. User Journeys & Endpoints

### Unauthenticated Users
- **Splash Page:** Can only see the core philosophy of the DLP system and access the Login/Signup portals.

### Standard Registered Users
- **Simulate Leak (`/simulate`):** An educational portal where users can safely test the strictness of the DLP algorithms without consequences.
- **Send Email (`/send_email`):** A functional outbound communication proxy. Users attempt to send emails (with optional attachments). The DLP core intercepts the transmission. If a Tier 1 or Tier 2 match triggers, the email is blocked.

### Administrators
Administrators bypass standard checks and receive elevated privileges.
- **Register Data (`/register`):** Admins can upload specific highly-restrictive files to add them to the `sensitive_hashes` database.
- **Logs Dashboard (`/logs`):** A live feed depicting all `Allowed` and `Blocked` transactions happening globally across the network.
- **Admin Panel (`/admin`):** A specialized diagnostic hub allowing the administrator to inspect raw cryptographic hash registries.

---

## 5. Security & Threat Model

### Targeted Attack Vectors
1. **The Careless Insider:** An employee accidentally pasting proprietary internal memos into a public email body to a client.
2. **The Malicious Exfiltrator:** A compromised employee attempting to upload restricted financial PDFs to random web servers.
3. **The Obfuscator:** An attacker slightly modifying a file (e.g., changing headers or text spacing) to trick simple hash-matching DLP systems. (Resolved via Tier 2 Fuzzy Hashing).

### Implemented Safeguards
- Raw sensitive data is **never stored**. Only abstract hashes reside on the server, mitigating the risk of the DLP database itself being breached.
- All passwords are incrementally hashed to prevent credential stuffing.
- Server-side sessions explicitly lock endpoints ensuring role-based access control.
