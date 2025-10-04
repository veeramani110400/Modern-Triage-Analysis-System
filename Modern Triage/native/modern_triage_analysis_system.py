import os
import subprocess
import re
import logging
import datetime
from pathlib import Path
import requests
import json
from bs4 import BeautifulSoup
import json
import pefile
import time
import uuid
from collections import defaultdict
import traceback

# Hardcoded malware path (as requested)
MALWARE_PATH = r"E:\testExes\a.exe"
REPORT_FILE = r"..\\Reports\Sample1_report.txt"
SIGNATURE_DB_FILE = "file_signatures.json"
MALAPI_DB_FILE = "malapi_data.json"
MALICIOUS_KEYWORDS_FILE = "malicious_keywords.json"

# Set up logging to Report.txt
logging.basicConfig(filename=REPORT_FILE, level=logging.INFO, format='%(message)s')

# Dictionary of important keywords for string comparison
IMPORTANT_KEYWORDS = [
    "password", "key", "encrypt", "decrypt", "admin", "login", "credential",
    "backdoor", "exploit", "shellcode", "ransomware", "command", "control"
]

def log_message(message):
    """Log message to Report.txt with timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"[{timestamp}] {message}")

def module1_file_type_identification(malware_path):
    """Run Detect It Easy twice: with JSON for entropy/packing and text for language/compiler/architecture/linker/endianness."""
    log_message("\n\n\n=== Module 1: Detect It Easy Analysis ===")
    try:
        #die_path = r"C:\Users\veera\Desktop\die_win64_portable_3.10_x64\diec.exe"
        die_path =  r"..\\dependencies\die_win64_portable_3.10_x64\diec.exe"
        # Verify DIE executable exists
        if not os.path.exists(die_path):
            log_message(f"Error: Detect It Easy executable not found at {die_path}")
            return None
        
        # Verify malware file exists
        if not os.path.exists(malware_path):
            log_message(f"Error: Malware file not found at {malware_path}")
            return None

        # Initialize parsed data
        parsed_data = {
            "File Type": None,
            "Architecture": None,
            "Compiler": None,
            "Linker": None,
            "Language": None,
            "Packer": None,
            "Entropy": None,
            "Tool": None,
            "Sign Tool": None,
            "Sections": [],
            "Overlay": None,
            "Endianness": None,  # Added for endianness
            "Other": []
        }

        # First Run: JSON output with heuristic, deep scan, and entropy
        log_message("Running DIE with JSON output for entropy and packing analysis")
        command_json = [die_path, malware_path, "--heuristicscan", "--deepscan", "--entropy", "--json"]
        log_message(f"Executing command: {' '.join(command_json)}")
        try:
            result_json = subprocess.run(
                command_json,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result_json.returncode != 0:
                log_message(f"Error: Detect It Easy (JSON) exited with code {result_json.returncode}")
                log_message(f"stderr: {result_json.stderr}")
            elif result_json.stdout:
                try:
                    json_data = json.loads(result_json.stdout)
                    # Extract entropy and packing info
                    if "total" in json_data:
                        parsed_data["Entropy"] = str(json_data["total"])
                    if "status" in json_data:
                        parsed_data["Packer"] = json_data["status"].capitalize()
                    if "records" in json_data:
                        for record in json_data["records"]:
                            if record.get("name") == "Overlay":
                                parsed_data["Overlay"] = f"Present, Size={record.get('size', 0)} bytes, Entropy={record.get('entropy', 0):.2f}, Status={record.get('status', 'unknown')}"
                            elif "Section" in record.get("name", ""):
                                parsed_data["Sections"].append(
                                    f"{record.get('name')}: Size={record.get('size', 0)} bytes, Entropy={record.get('entropy', 0):.2f}, Status={record.get('status', 'unknown')}"
                                )
                            # Check for endianness in JSON (if available, e.g., for ELF/Mach-O)
                            if record.get("endian"):
                                parsed_data["Endianness"] = record.get("endian").capitalize()
                    if result_json.stderr:
                        parsed_data["Other"].append(f"JSON Warnings: {result_json.stderr}")
                except json.JSONDecodeError as e:
                    log_message(f"Error parsing DIE JSON output: {str(e)}")
                    log_message(f"Raw JSON output: {result_json.stdout}")
            else:
                log_message("Detect It Easy (JSON) produced no output")
        except subprocess.TimeoutExpired:
            log_message("Error: Detect It Easy (JSON) timed out after 300 seconds")
        except subprocess.SubprocessError as e:
            log_message(f"Subprocess error running Detect It Easy (JSON): {str(e)}")

        # Second Run: Text output for language, compiler, architecture, linker, endianness
        log_message("Running DIE with text output for metadata analysis")
        command_text = [die_path, malware_path]
        log_message(f"Executing command: {' '.join(command_text)}")
        try:
            result_text = subprocess.run(
                command_text,
                capture_output=True,
                text=True,
                timeout=300
            )
            if result_text.returncode != 0:
                log_message(f"Error: Detect It Easy (Text) exited with code {result_text.returncode}")
                log_message(f"stderr: {result_text.stderr}")
            elif result_text.stdout:
                # Parse text output
                patterns = {
                    "File Type": r"^(PE32|PE64|ELF|Mach-O)",
                    "Architecture": r"^(PE32|PE64|ELF|Mach-O|x86|x64|ARM|ARM64)",
                    "Linker": r"Linker: (.+)",
                    "Compiler": r"Compiler: (.+)",
                    "Tool": r"Tool: (.+)",
                    "Sign Tool": r"Sign tool: (.+)",
                    "Packer": r"Packer: (.+)",
                    "Endianness": r"Endianness: (Little|Big)"  # Added for endianness
                }
                for line in result_text.stdout.splitlines():
                    line = line.strip()
                    if not line or "[!]" in line:
                        continue
                    matched = False
                    for key, pattern in patterns.items():
                        match = re.match(pattern, line)
                        if match:
                            parsed_data[key] = match.group(1)
                            matched = True
                            break
                    if not matched:
                        parsed_data["Other"].append(line)
                
                # Infer Language from Compiler or Tool
                if parsed_data["Compiler"] or parsed_data["Tool"]:
                    compiler_tool = (parsed_data["Compiler"] or parsed_data["Tool"]).lower()
                    if "c++" in compiler_tool or "visual c" in compiler_tool:
                        parsed_data["Language"] = "C/C++"
                    elif "delphi" in compiler_tool:
                        parsed_data["Language"] = "Pascal"
                    elif "go" in compiler_tool:
                        parsed_data["Language"] = "Go"
                    elif "dotnet" in compiler_tool or ".net" in compiler_tool:
                        parsed_data["Language"] = "C#"
                    elif "python" in compiler_tool:
                        parsed_data["Language"] = "Python"
                
                if result_text.stderr:
                    parsed_data["Other"].append(f"Text Warnings: {result_text.stderr}")
            else:
                log_message("Detect It Easy (Text) produced no output")
        except subprocess.TimeoutExpired:
            log_message("Error: Detect It Easy (Text) timed out after 300 seconds")
        except subprocess.SubprocessError as e:
            log_message(f"Subprocess error running Detect It Easy (Text): {str(e)}")

        # Log parsed results
        log_message("\n\nParsed Detect It Easy Results:")
        for key, value in parsed_data.items():
            if value:
                if key in ["Sections", "Other"] and value:
                    log_message(f"{key}:\n" + "\n".join(value))
                else:
                    log_message(f"{key}: {value}")

        # Log raw outputs for debugging
        if result_json.stdout:
            log_message(f"Raw JSON Output:\n{json.dumps(json.loads(result_json.stdout), indent=2)}")
        if result_text.stdout:
            log_message(f"Raw Text Output:\n{result_text.stdout}")

        return parsed_data

    except Exception as e:
        log_message(f"Unexpected error in module1_detect_it_easy: {str(e)}\nTraceback: {traceback.format_exc()}")
        return None

def module2_strings_extraction(malware_path):
    """Extract strings using strings.exe and floss.exe, apply regex, and check against malicious keyword database."""
    log_message("\n\n\n=== Module 2: String Extraction and Analysis ===")
    
    # Enhanced regex patterns
    patterns = {
        "URL": r"https?://[^\s]+",
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "IP": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "FilePath": r"[A-Za-z]:\\[^<>:\"|?*]+",
        "Registry": r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|SOFTWARE)[^;\n]*",
        "API": r"(?:CreateRemoteThread|WriteProcessMemory|VirtualAlloc|GetProcAddress|LoadLibrary|ShellExecute|RegSetValue|CryptEncrypt|CryptDecrypt)\w*",
        "Crypto": r"(?:AES|RSA|SHA1|SHA256|MD5|HMAC|DES|3DES|RC4|keygen|hash|crypto)\b",
        "Command": r"(?:cmd\.exe|powershell\.exe|regsvr32\.exe|rundll32\.exe|netsh|wmic)\b"
    }
    
    # Load or create malicious keywords database
    def load_malicious_keywords():
        """Load malicious keywords from JSON file or create if not exists."""
        try:
            if os.path.exists(MALICIOUS_KEYWORDS_FILE):
                # --- FIX: Added encoding="utf-8" ---
                with open(MALICIOUS_KEYWORDS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            
            # Create sample malicious keywords
            keywords = [
                "password", "psswrd", "passwrd", "pwd", "credential", "login", "username", "auth", "token", "secret",
                "encrypt", "decrypt", "encryption", "decryption", "AES", "RSA", "SHA1", "SHA256", "MD5", "HMAC",
                "DES", "3DES", "RC4", "keygen", "hash", "crypto", "cipher", "plaintext", "keylogger", "keystroke",
                "backdoor", "ransomware", "trojan", "worm", "virus", "spyware", "malware", "exploit", "shellcode", "payload",
                "attack", "inject", "hook", "rootkit", "botnet", "command", "control", "c2", "exfiltrate", "persistence",
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc", "GetProcAddress", "LoadLibrary", "ShellExecute",
                "RegSetValue", "CryptEncrypt", "CryptDecrypt", "OpenProcess", "VirtualProtect", "CreateProcess", "NtWrite",
                "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe", "netsh", "wmic", "taskkill", "schtasks",
                "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "SOFTWARE", "Run", "RunOnce",
                "http", "https", "ftp", "smtp", "dns", "proxy", "tor", "onion", "tcp", "udp", "socket", "bind", "connect",
                "obfuscate", "packer", "upx", "aspack", "pecompact", "cryptor", "stealth", "polymorphic", "metamorphic",
                *[f"malicious_{i}" for i in range(1, 401)]
            ]
            # --- FIX: Added encoding="utf-8" ---
            with open(MALICIOUS_KEYWORDS_FILE, "w", encoding="utf-8") as f:
                json.dump(keywords, f)
            log_message(f"Created malicious keywords database with {len(keywords)} entries")
            return keywords
        except Exception as e:
            log_message(f"Error loading/creating malicious keywords: {str(e)}")
            return []

    malicious_keywords = load_malicious_keywords()

    # Run strings.exe
    try:
        strings_path = r"..\\dependencies\Strings\strings64.exe"
        if not os.path.exists(strings_path):
            log_message(f"Error: strings.exe not found at {strings_path}")
            return
        
        command = [strings_path, "-n", "6", "-accepteula" , malware_path]
        log_message(f"Executing strings.exe command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=500)
        
        if result.returncode != 0:
            log_message(f"Error: strings.exe exited with code {result.returncode}")
            log_message(f"stderr: {result.stderr}")
            return
        
        strings_output = result.stdout
        if not strings_output.strip():
            log_message("strings.exe produced no output")
            return

        string_list = [s.strip() for s in strings_output.splitlines() if s.strip()]
        log_message(f"Extracted {len(string_list)} strings from strings.exe")

        for key, pattern in patterns.items():
            matches = [s for s in string_list if re.search(pattern, s, re.IGNORECASE)]
            if matches:
                log_message(f"{key} matches found ({len(matches)}):\n" + "\n".join(matches))
            else:
                log_message(f"No {key} matches found.")

        found_keywords = [(s, kw) for s in string_list for kw in malicious_keywords if kw.lower() in s.lower()]
        if found_keywords:
            log_message(f"Malicious keywords found ({len(found_keywords)}):")
            for s, kw in found_keywords:
                log_message(f"String: {s}, Matched Keyword: {kw}")
        else:
            log_message("No malicious keywords found.")

        dos_stub_count = strings_output.lower().count("this program cannot be run in dos mode")
        log_message(f"MS-DOS Stub Count: {dos_stub_count}")

    except subprocess.TimeoutExpired:
        log_message("Error: strings.exe timed out after 300 seconds")
    except subprocess.SubprocessError as e:
        log_message(f"Subprocess error running strings.exe: {str(e)}")
    except Exception as e:
        log_message(f"Unexpected error in strings.exe: {str(e)}\nTraceback: {traceback.format_exc()}")

def module3_dissecting_pe_header(malware_path):
    """Dissect PE Header to extract compiler timestamp, subsystem, .text section details, and imports."""
    log_message("\n\n\n=== Module 3: PE Header Analysis ===")
    try:
        pe = pefile.PE(malware_path)
        
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        log_message(f"Compiler Timestamp: {compile_time}")
        
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem, "Unknown")
        log_message(f"Subsystem: {subsystem_name}")
        
        for section in pe.sections:
            if section.Name.decode().strip("\x00").lower() == ".text":
                log_message(f".text Section - Raw Data Size: {section.SizeOfRawData}")
                log_message(f".text Section - Virtual Size: {section.Misc_VirtualSize}")
                break
        else:
            log_message(".text section not found.")
            
    except Exception as e:
        log_message(f"Error analyzing PE header: {str(e)}")

def module4_capa(malware_path):
    """Run capa.exe to analyze malware capabilities."""
    log_message("\n\n\n=== Module 4: Capa Analysis ===")
    try:
        capa_path = r"..\\dependencies\capa\capa.exe"
        if not os.path.exists(capa_path):
            log_message(f"Error: capa.exe not found at {capa_path}")
            return
        if not os.path.exists(malware_path):
            log_message(f"Error: Malware file not found at {malware_path}")
            return
        
        command = [capa_path, malware_path]
        log_message(f"Executing command: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                encoding='utf-8',
                errors='replace'
            )
            if result.stdout:
                log_message("capa.exe Output:\n" + result.stdout)
            else:
                log_message("capa.exe produced no output (stdout is empty)")
            if result.stderr:
                log_message("capa.exe Errors:\n" + result.stderr)
            if result.returncode != 0:
                log_message(f"capa.exe exited with code {result.returncode}")
        except subprocess.TimeoutExpired:
            log_message("Error: capa.exe timed out after 300 seconds")
        except Exception as e:
            log_message(f"Unexpected subprocess error: {str(e)}")
            
    except Exception as e:
        log_message(f"Unexpected error in module4_capa: {str(e)}\nTraceback: {traceback.format_exc()}")

def module5_remove_hidden_attributes(start_path):
    """Recursively remove hidden attributes from files and folders starting from the specified directory."""
    log_message("\n\n\n=== Module 5: Remove Hidden Attributes ===")
    try:
        attrib_path = r"C:\Windows\System32\attrib.exe"
        hidden_items = []

        def remove_hidden_attribute(item_path):
            try:
                attrib_result = subprocess.run([attrib_path, item_path], capture_output=True, text=True)
                if "H" in attrib_result.stdout or "S" in attrib_result.stdout:
                    subprocess.run([attrib_path, "-H", "-S", item_path], check=True)
                    hidden_items.append(item_path)
                    log_message(f"Removed hidden/system attributes from: {item_path}")
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                log_message(f"Error processing {item_path}: {str(e)}")

        for root, _, files in os.walk(start_path):
            remove_hidden_attribute(root)
            for file in files:
                file_path = os.path.join(root, file)
                remove_hidden_attribute(file_path)

        if hidden_items:
            log_message("Hidden or system items found and processed:\n" + "\n".join(hidden_items))
        else:
            log_message("No hidden or system items found.")
            
    except Exception as e:
        log_message(f"Error in attrib processing: {str(e)}\nTraceback: {traceback.format_exc()}")

def module6_checking_malicious_imports(malware_path):
    """Load malapi_imports.json, compare with PE file imports, and group by MITRE ATT&CK technique."""
    log_message("\n\n\n=== Module 6: MalAPI.io Import Comparison ===")
    
    def load_malapi_data():
        """Load or create malapi_imports.json with API-to-technique mappings."""
        try:
            if os.path.exists(MALAPI_DB_FILE):
                # --- FIX: Added encoding="utf-8" ---
                with open(MALAPI_DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)

            malapi_data = {
                "Enumeration": ["CreateToolhelp32Snapshot", "EnumProcesses", "GetModuleBaseNameA"],
                "Injection": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"],
                "Evasion": ["Sleep", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                "Spying": ["GetAsyncKeyState", "GetForegroundWindow", "SetWindowsHookExA"],
                "Internet": ["InternetOpenA", "InternetConnectA", "HttpSendRequestA"],
                "Ransomware": ["CryptAcquireContextA", "CryptEncrypt", "CryptGenKey"],
            }
            # --- FIX: Added encoding="utf-8" ---
            with open(MALAPI_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(malapi_data, f, indent=2)
            log_message(f"Created malapi_imports.json with {len(malapi_data)} categories")
            return malapi_data
        except Exception as e:
            log_message(f"Error loading/creating malapi_imports.json: {str(e)}")
            return {}

    try:
        if not os.path.exists(malware_path):
            log_message(f"Error: Malware file not found at {malware_path}")
            return
        
        pe = pefile.PE(malware_path)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8', errors='ignore'))
        
        if not imports:
            log_message("No imports found in PE file.")
            return

        malapi_data = load_malapi_data()
        if not malapi_data:
            log_message("No malapi.io data available for comparison.")
            return

        category_to_mitre = {
            "Enumeration": {"tactic": "Discovery", "technique": "System Information Discovery (T1082)"},
            "Injection": {"tactic": "Execution", "technique": "Process Injection (T1055)"},
            "Evasion": {"tactic": "Defense Evasion", "technique": "Debugger Evasion (T1622)"},
            "Spying": {"tactic": "Collection", "technique": "Input Capture (T1056)"},
            "Internet": {"tactic": "Command and Control", "technique": "Application Layer Protocol (T1071)"},
            "Ransomware": {"tactic": "Impact", "technique": "Data Encrypted for Impact (T1486)"}
        }

        matches_by_technique = defaultdict(list)
        for imp in imports:
            for category, apis in malapi_data.items():
                if imp in apis:
                    technique_info = category_to_mitre.get(category, {})
                    matches_by_technique[technique_info.get("technique", "Unknown")].append({
                        "api": imp,
                        "tactic": technique_info.get("tactic", "Unknown"),
                        "category": category
                    })
                    break

        if matches_by_technique:
            log_message(f"Found {sum(len(v) for v in matches_by_technique.values())} matching APIs grouped by MITRE ATT&CK technique:")
            for technique, api_list in matches_by_technique.items():
                log_message(f"\n--- Technique: {technique} ---")
                for api_info in api_list:
                    log_message(f"  - API: {api_info['api']} (Tactic: {api_info['tactic']}, Category: {api_info['category']})")
        else:
            log_message("No matching malicious APIs found.")

    except pefile.PEFormatError as e:
        log_message(f"Error: Invalid PE file format: {str(e)}")
    except Exception as e:
        log_message(f"Unexpected error in module6_malapi_imports: {str(e)}\nTraceback: {traceback.format_exc()}")

def reverse_hex_signature(hex_string):
    """Reverse a hex string byte by byte."""
    hex_string = hex_string.replace(" ", "")
    byte_list = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return "".join(reversed(byte_list))

def module7_check_file_signature(file_path, signatures_by_ext, mismatches):
    """Check a single file's signature against a pre-processed signature dict."""
    try:
        ext = os.path.splitext(file_path)[1].lower().lstrip(".")
        if ext not in signatures_by_ext:
            return

        max_len = max((len(sig["signature"]) // 2 for sig in signatures_by_ext[ext]), default=16)

        with open(file_path, "rb") as f:
            file_data = f.read(max_len + 64)

        matched = False
        for sig_info in signatures_by_ext[ext]:
            pattern = sig_info["signature"].replace("??", "..")
            offset = sig_info["offset"]
            sig_len = len(sig_info["signature"]) // 2
            found_bytes = file_data[offset:offset + sig_len].hex().lower()

            if re.match(f"^{pattern}$", found_bytes):
                matched = True
                break
            reversed_pattern = reverse_hex_signature(sig_info["signature"]).replace("??", "..")
            if re.match(f"^{reversed_pattern}$", found_bytes):
                matched = True
                break

        if not matched:
            expected_sigs = ", ".join([s["signature"] for s in signatures_by_ext[ext]])
            mismatches.append({
                "file": file_path,
                "extension": ext,
                "found_signature": file_data[:16].hex(),
                "expected_signatures": expected_sigs,
                "expected_types": ", ".join(s["description"] for s in signatures_by_ext[ext])
            })
    except Exception as e:
        log_message(f"Error checking signature for {file_path}: {str(e)}")



def module7_scan_directory_for_signatures(directory_path):
    """Loads signatures and scans all files in a directory for mismatches."""
    log_message("\n\n\n=== Module 7: File Signature Verification ===")
    
    import re
    from collections import defaultdict
    import os
    import json

    try:
        # --- FIX: Added encoding="utf-8" ---
        with open(SIGNATURE_DB_FILE, "r", encoding="utf-8") as f:
            signatures = json.load(f)
    except FileNotFoundError:
        log_message(f"Error: Signature database not found at {SIGNATURE_DB_FILE}")
        return
    except json.JSONDecodeError as e:
        log_message(f"Error: Could not decode JSON from {SIGNATURE_DB_FILE}. Details: {e}")
        return
    except Exception as e:
        log_message(f"Error loading signature database: {str(e)}")
        return

    signatures_by_ext = defaultdict(list)
    # --- NEW: Create a signature-to-type mapping for found signature lookup ---
    signature_to_type = {}
    
    for sig in signatures:
        ext_str = sig.get("Extension", "").lower().replace("\n", " ")
        exts = [e.strip() for e in ext_str.split() if e.strip()]

        hex_full = sig.get("Hex_signature", "").strip()
        # Remove parentheticals and split on them if multiple
        hex_parts = re.sub(r'\s*\([^)]*\)', '|', hex_full).split('|')
        hex_sigs = [h.strip() for h in hex_parts if h.strip()]

        offset_str = sig.get("Offset", "0")
        # Extract the first valid number from offset
        match = re.search(r'\b(\d+|0x[0-9a-fA-F]+)\b', offset_str)
        if match:
            offset_val = match.group(1)
            try:
                if offset_val.startswith('0x'):
                    offset = int(offset_val, 16)
                else:
                    offset = int(offset_val)
            except ValueError:
                offset = 0
        else:
            offset = 0

        for hex_sig in hex_sigs:
            # Clean hex_sig: replace spaces, lower, ignore ??
            signature = hex_sig.lower().replace(" ", "").replace("??", "..")  # Placeholder for wildcards if needed

            # --- NEW: Map cleaned signature to description for type lookup ---
            description = sig.get("Description", "Unknown")
            signature_to_type[signature] = description

            for ext in exts:
                signatures_by_ext[ext].append({
                    "signature": signature,
                    "description": description,
                    "offset": offset
                })

    mismatches = []
    log_message(f"Scanning directory for signature mismatches: {directory_path}")

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            module7_check_file_signature(file_path, signatures_by_ext, mismatches)

    if mismatches:
        log_message(f"Found {len(mismatches)} file signature mismatches:")
        for mismatch in mismatches:
            # --- NEW: Attempt to find the file type for the found signature ---
            found_signature = mismatch['found_signature'].lower().replace(" ", "")
            found_type = "Unknown"
            for sig, desc in signature_to_type.items():
                if found_signature.startswith(sig.replace("..", "")):  # Ignore wildcards for matching
                    found_type = desc
                    break

            log_message(
                f"-> Mismatch in file: {mismatch['file']}\n"
                f"   Extension: .{mismatch['extension']}\n"
                f"   Expected Type(s): {mismatch['expected_types']}\n"
                f"   Expected Signature(s): {mismatch['expected_signatures']}\n"
                f"   Found Signature (start): {mismatch['found_signature']}\n"
                f"   Found Signature matches type: {found_type}"  # --- NEW: Add matched type ---
            )
    else:
        log_message("No file signature mismatches found in the scanned directory.")

# Main execution
def main():
    log_message("=== Malware Analysis Started ===")
    start_path = os.path.dirname(MALWARE_PATH)
    
    module1_file_type_identification(MALWARE_PATH)
    module2_strings_extraction(MALWARE_PATH)
    module3_dissecting_pe_header(MALWARE_PATH)
    module4_capa(MALWARE_PATH)
    module5_remove_hidden_attributes(start_path)
    module6_checking_malicious_imports(MALWARE_PATH)
    module7_scan_directory_for_signatures(start_path)
    
    log_message("=== Malware Analysis Completed ===")

if __name__ == "__main__":
    main()