
---

# 🛡️ Modern Malware Triage Analysis System

This project is a **modular malware triage framework** built in Python that automates multiple stages of **malware static analysis**.
It integrates popular tools and custom modules to quickly extract metadata, detect suspicious indicators, and generate a detailed **forensic report**.

---

## 📌 Features

* **File Type & Packing Detection (Module 1)**
  Uses **Detect It Easy (DIE)** to extract file type, architecture, compiler, linker, entropy, overlay details, and packing/obfuscation indicators.

* **String Extraction & Keyword Matching (Module 2)**
  Extracts printable strings via **strings.exe** and checks against **regex patterns** (URLs, IPs, registry paths, API calls) and a **malicious keyword database**.

* **PE Header Analysis (Module 3)**
  Parses **PE headers** with `pefile` to extract:

  * Compile timestamp
  * Subsystem
  * `.text` section details

* **Capability Detection with capa (Module 4)**
  Runs **capa** to identify malware capabilities (persistence, injection, encryption, etc.) mapped to MITRE ATT&CK.

* **Hidden Attribute Removal (Module 5)**
  Recursively detects and removes hidden/system file attributes (useful for unpacking droppers).

* **Malicious Import Detection (Module 6)**
  Matches PE imports against **MalAPI.io** database and groups them by **MITRE ATT&CK techniques**.

* **File Signature Verification (Module 7)**
  Compares file magic numbers against a **file signature database** (`file_signatures.json`) to detect **disguised or tampered files**.

* **Centralized Logging**
  All results are saved into a timestamped **report file** (`Reports/Sample1_report.txt`).

---

## 🛠️ Requirements

* Python 3.8+
* Dependencies:

  ```bash
  pip install pefile requests beautifulsoup4
  ```
* External tools (must be placed in `dependencies/`):

  * [Detect It Easy (diec.exe)](https://github.com/horsicq/DIE-engine)
  * [Strings (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
  * [capa](https://github.com/mandiant/capa)

---

## 📂 Project Structure

```
├── dependencies/
│   ├── die_win64_portable_3.10_x64/diec.exe
│   ├── Strings/strings64.exe
│   ├── capa/capa.exe
├── Reports/
│   └── Sample1_report.txt
├── file_signatures.json
├── malapi_data.json
├── malicious_keywords.json
├── malware_triage.py   ← main script
```

---

## 🚀 Usage

1. Place the malware sample in your analysis directory.
2. Update the **`MALWARE_PATH`** in the script (`malware_triage.py`).
3. Run the tool:

   ```bash
   python modern_triage_analysis_system.py
   ```
4. View the generated report:

   ```
   Reports/Sample1_report.txt
   ```

---

## 📖 Example Report (snippet)

```
=== Module 1: Detect It Easy Analysis ===
File Type: PE32
Architecture: x86
Compiler: Visual C++
Entropy: 7.6 (packed/suspicious)

=== Module 2: String Extraction and Analysis ===
URL matches found (2):
http://malicious.example.com
https://c2.server.net
Malicious keywords found (5):
String: admin_login, Matched Keyword: login

=== Module 6: MalAPI.io Import Comparison ===
--- Technique: Process Injection (T1055) ---
  - API: CreateRemoteThread (Tactic: Execution, Category: Injection)
```

---

## ⚠️ Disclaimer

This tool is built for **educational, research, and red team purposes only**.
Do not use it on live systems without authorization.
Always run malware samples in a **controlled, isolated environment** (e.g., VM/sandbox).

---

