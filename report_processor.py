import re
import json
import pandas as pd
from langchain_community.document_loaders import TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from tqdm import tqdm
from langchain_groq import ChatGroq
from config import GROQ_API_KEY, GROQ_MODEL_NAME, TEMPERATURE, CHAT_TEMPLATE
import xml.etree.ElementTree as ET
import datetime
import os
from io import StringIO

def is_param(line):
    return re.fullmatch(r"[a-zA-Z0-9_]+", line) is not None

def is_target(line):
    url_pattern = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$"
    )
    ip_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    )
    return bool(
        url_pattern.match(line) or
        ip_pattern.match(line) or
        domain_pattern.match(line)
    )



# You'd need to import ChatGroq if you're using it directly, 
# or this could be passed in as a parameter to the function

# Dictionary mapping tools to their cleaning functions
TOOL_CLEANERS = {
    "XSStrike": "clean_xsstrike_output",
    "XSSVibes": "clean_xssvibes_output",
    "XSpear": "clean_xspear_output",
    "PwnXSS": "clean_pwnxss_output",
    "XSSer": "clean_xsser_output",
    "WhatWeb": "clean_whatweb_output",
    "Wafw00f": "clean_wafw00f_output",
    "SHCheck": "clean_shcheck_output",
    "S3Scanner": "clean_s3scanner_output",
    "PPFuzz": "clean_ppfuzz_output",
    "CSP Analyzer": "clean_csp_analyzer_output",
    "Clickjacking Tester": "clean_clickjacking_tester_output",
    "SQLMap": "clean_sqlmap_output",
    "SSLscan": "clean_sslscan_output",
    "SSLyze": "clean_sslyze_output",
    "TestSSL": "clean_testssl_output",
    "Wapiti": "clean_wapiti_output",
    "Dig": "clean_dig_output",
    "DNScan": "clean_dnscan_output",
    "DNSenum": "clean_dnsenum_output",
    "DNSrecon": "clean_dnsrecon_output",
    "Gobuster": "clean_gobuster_output",
    "Ffuf": "clean_ffuf_output",
    "Wfuzz": "clean_wfuzz_output",
    "Dirsearch": "clean_dirsearch_output",
    "Httpx": "clean_httpx_output",
    "Assetfinder": "clean_assetfinder_output",
    "Sublist3r": "clean_sublist3r_output",
    "Arjun": "clean_arjun_output"
}

# Module-specific report generation templates
MODULE_TEMPLATES = {
    "XSS": """
Generate a consolidated security report. If there is a false positive or failed result in any output, say 'This is a FALSE POSITIVE' only and DO NOT output anything else
    Otherwise strictly follow the format, ensuring that payloads are NOT repeated and payloads with same methods [GET/POST etc] and parameters are listed together:

    Target: [Extracted Target]

    **Vulnerabilities Found:**

    **[Vulnerability Name]**
    * Method: [GET/POST/OTHER]
    * Parameter: [Extracted Parameter]
    * Payloads:
        + [Payload 1]
        + [Payload 2]

    Tools:
{text}
""",
    "InfoScanner": """
Extract web information findings from the following scanner outputs. Include vital information as needed, such as URLs, payloads, parameters etc
Tool outputs:
{text}
""",
    "SQLi": """ """,
    "SSL": """
Extract SSL/TLS security issues from the following outputs.

Tool outputs:
{text}
""",
    "WebScanner": """ """,
    "DNS": """
Extract important information from these DNS tool findings
{text}
""", 
    "Assetfinder": """
Extract important information from these DNS tool findings
{text}
""", 

    "Misc": """ """
}

def process_nmap_chunked(content):
    try:
        #tree = ET.parse(content)
        root = ET.fromstring(content)
        ns = {}

        report = {
            "Scan Metadata": {},
            "Target Information": {},
            "Open Ports and Services": {},
            "Filtered Ports": {},
            "Security Observations": {
                "Shared SSL Certificates": set(),
                "403 Forbidden on web ports": [],
                "Exposed Database Ports": [],
                "TLS Issues": []
            }
        }

        # Scan metadata
        if 'args' in root.attrib:
            report["Scan Metadata"]["command"] = root.attrib['args']
            report["Scan Metadata"]["version"] = root.attrib.get('version')

        # Target information
        host = root.find('host')
        if host is not None:
            status = host.find('status')
            address = host.find('address')
            hostname = host.find('hostnames/hostname')

            report["Target Information"] = {
                "status": status.attrib['state'] if status is not None else None,
                "ip": address.attrib['addr'] if address is not None else None,
                "hostname": hostname.attrib['name'] if hostname is not None else None
            }

            # Filtered ports
            extraports = host.find('ports/extraports')
            if extraports is not None and extraports.attrib.get('state') == 'filtered':
                report["Filtered Ports"]["filtered_tcp_ports"] = extraports.attrib.get('count')

            # Open ports and services
            for port in host.findall('ports/port'):
                port_id = port.attrib['portid']
                state = port.find('state').attrib['state']
                service_elem = port.find('service')
                scripts = port.findall('script')

                service_name = service_elem.attrib.get('product') if service_elem is not None else None

                port_info = {
                    "state": state,
                    "service": service_name,
                    "details": {}
                }

                for script in scripts:
                    sid = script.attrib.get('id')
                    output = script.attrib.get('output', '')
                    port_info["details"][sid] = output

                    # Collect Security Observations
                    if sid == "ssl-cert":
                        if "commonName=" in output:
                            cn_line = next((line for line in output.split('\n') if "commonName=" in line), "")
                            cn = cn_line.split("commonName=")[-1].split()[0]
                            report["Security Observations"]["Shared SSL Certificates"].add(cn)

                    if sid == "ssl-date" and "randomness does not represent time" in output:
                        report["Security Observations"]["TLS Issues"].append(f"Port {port_id}")

                    if sid == "fingerprint-strings" and "403 Forbidden" in output:
                        report["Security Observations"]["403 Forbidden on web ports"].append(f"Port {port_id}")

                    if port_id == "3306":
                        report["Security Observations"]["Exposed Database Ports"].append("3306")

                report["Open Ports and Services"][f"Port {port_id}"] = port_info

        # Convert sets to lists for JSON compatibility
        report["Security Observations"]["Shared SSL Certificates"] = list(report["Security Observations"]["Shared SSL Certificates"])
        

        return json.dumps(report, indent=2)
    except ET.ParseError as e:
        # Handle XML parsing errors
        return f"Error parsing Nmap XML: {str(e)}\nContent preview: {content[:200]}..."

# Updated tool report processor



# === Cleaning Functions for XSS Tools ===

def process_xss(full_text):
    prompt_text = f"""Extract XSS vulnerabilities from the following text.  If there is a false positive or failed result say that there is a false positive

    Target: [Extracted Target]

    **Vulnerabilities Found:**

    **[Vulnerability Name]**
    * Method: [GET/POST/OTHER]
    * Parameter: [Extracted Parameter]
    * Payloads:
        + [Payload 1]
        + [Payload 2]

    Text:
    {full_text}"""
    chat = ChatGroq(
    temperature=0,
    groq_api_key=GROQ_API_KEY,
    model_name=GROQ_MODEL_NAME
    )
    response = chat.invoke(prompt_text)
    res = response.content
    return res


def clean_xsstrike_output(content):
    output = ""
    if "No reflection found" in content:
        return "No XSS reflections found in the file."

    # Extract parameter
    param_match = re.search(r"Testing parameter:\s+(\w+)", content)
    parameter = param_match.group(1) if param_match else "Unknown"

    # Extract payload-confidence pairs
    payload_conf_matches = re.findall(
        r"Payload:\s+(<[^>]+>)\s+.*?Confidence:\s+(\d+)", content, re.DOTALL)

    # Filter by confidence > 50
    valid_payloads = [payload for payload, conf in payload_conf_matches if int(conf) > 10]
    unique_payloads = list(dict.fromkeys(valid_payloads))  # Remove duplicates

    if not unique_payloads:
        return " "

    # Build report string
    output += "**Vulnerabilities Found:**\n\n"
    output += "**Reflected XSS**\n"
    output += "* Method: GET\n"
    output += f"* Parameter: {parameter}\n"
    output += "* Payloads:\n"

    for payload in unique_payloads:
        output += f"    + {payload}\n"

    return output

def clean_xssvibes_output(content):
    """Clean XSSVibes output"""
    # Skip header information
    lines = content.splitlines()
    start_index = next((i for i, line in enumerate(lines) if "scanning" in line.lower() or "payload" in line.lower()), 0)
    
    # Get relevant content
    relevant_lines = "\n".join(lines[start_index:])
    rel = process_xss(relevant_lines)
    return rel

def clean_xspear_output(content):
    """Clean XSpear output"""
    cleaned_text = re.sub(r"< Raw Query >.*", "", content, flags=re.DOTALL)
    cleaned_text = cleaned_text.strip()
    rel = process_xss(cleaned_text)
    return rel

def clean_pwnxss_output(content):
    """Clean PwnXSS output"""
    data = content

    results = []
    targets = {}

    # Match GET requests with potential XSS payloads
    pattern = re.compile(
        r'https://[^\s"]+\?(?P<param>\w+)=((?P<payload><script>.*?</script>)|(?P<encoded>%3Cscript%3E.*?%3C%2Fscript%3E))',
        re.IGNORECASE
    )
    
    for match in pattern.finditer(data):
        url = match.group(0)
        base = url.split('?')[0]
        param = match.group('param')
        payload = match.group('payload') or match.group('encoded')
        payload = re.sub('%3C', '<', payload)
        payload = re.sub('%3E', '>', payload)
        payload = re.sub('%28', '(', payload)
        payload = re.sub('%29', ')', payload)
        payload = re.sub('%2F', '/', payload)

        key = (base, param)
        if key not in targets:
            targets[key] = set()
        targets[key].add(payload)

    for (base, param), payloads in targets.items():
        result = f"Target: {base}\n\n**Vulnerabilities Found:**\n\n"
        result += f"**Reflected XSS in {param} Parameter**\n"
        result += f"* Method: GET\n"
        result += f"* Parameter: {param}\n"
        result += "* Payloads:\n"
        for p in sorted(payloads):
            result += f"    + {p}\n"
        results.append(result)

    final_output = "\n---\n\n".join(results)
    return final_output

def clean_xsser_output(content):
    cleaned_lines = []
    for line in content.splitlines():
        if re.fullmatch(r'\s*[=\-]+\s*', line):
            continue
        line = re.sub(r'^\s*\[[^\]]+\]\s*', '', line)
        if line.strip():
            cleaned_lines.append(line)
    cleaned_lines = '\n'.join(cleaned_lines)
    rel = process_xss(cleaned_lines)
    return rel

# === Cleaning Functions for InfoScanner Tools ===

def clean_whatweb_output(content):
    """Clean WhatWeb output"""
    # WhatWeb is usually already clean, but let's make it more concise
    return content.strip()

def clean_wafw00f_output(content):
    """Clean Wafw00f output"""
    return content.strip()

def clean_shcheck_output(content):
    """Clean SHCheck output"""
    return content.strip()

def clean_s3scanner_output(content):
    """Clean S3Scanner output"""
    return content.strip()

def clean_httpx_output(content):
    """Clean HTTPX output"""
    return content.strip()


# === Cleaning Functions for Assetfinder Tools ===

def clean_sublist3r_output(content):
    """Clean Sublist3r output"""
    return content.strip()

def clean_assetfinder_output(content):
    """Clean Assetfinder output"""
    return content.strip()

def clean_arjun_output(content):
    """Clean Arjun output"""
    if len(content) > 3:
        url = list(json.loads(content).keys())[0]
        info = json.loads(content)[url]
        headers = info.get("headers", {})
        return (str(headers) if headers else "No headers found").strip()
    else:
        return " "

# === Generic cleaning function for Misc tools ===

def clean_csp_analyzer_output(content):
    lines = content.splitlines()
    # Find the starting line of actual CSP content
    start_index = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("Calling"):
            start_index = i
            break
    
    # Extract relevant CSP lines
    content = "\n".join(lines[start_index:])

    # Create prompt for the LLM
    prompt_text = f"""Extract CSP information from this tool output and remove credits

Text:
{content}"""
    chat = ChatGroq(
        temperature=0,
        groq_api_key=GROQ_API_KEY,
        model_name=GROQ_MODEL_NAME
    )
    response = chat.invoke(prompt_text)
    print(type(response))
    print("Report generated successfully")
    return response.content

def clean_ppfuzz_output(content):
    lines = content.splitlines()

    # Find the starting line of actual CSP content
    start_index = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("Prototype"):
            start_index = i
            break

    # Print the cleaned content
    content= lines[start_index:]
    prompt_text = f"""Extract vulnerability information from this tool output and remove credits. If there is no vulnerability then say 'No prototype-pollution vulnerability'

        Text:
        {content}"""
    chat = ChatGroq(
        temperature=0,
        groq_api_key=GROQ_API_KEY,
        model_name=GROQ_MODEL_NAME
    )
    response = chat.invoke(prompt_text)
    print(type(response))
    print(f"Report generated successfully")
    return response.content

def clean_clickjacking_tester_output(content):
    content = content.splitlines()

    prompt_text = f"""Extract clickjacking vulnerability information from this tool output and remove credits

        Text:
        {content}"""
    chat = ChatGroq(
        temperature=0,
        groq_api_key=GROQ_API_KEY,
        model_name=GROQ_MODEL_NAME
    )
    response = chat.invoke(prompt_text)
    print(type(response))
    print(f"Report generated successfully")
    return response.content

def extract_sqlmap_insights(content):
    """
    Processes SQLMap output file by extracting key information using ChatGroq LLM.

    Args:
        input_file_path (str): Path to the SQLMap output log file.
        output_file_path (str, optional): If specified, saves the processed result to this file.
        groq_api_key (str): Your Groq API key.
        model_name (str): Model name for the Groq chat model.

    Returns:
        str: A single string containing the extracted insights.
    """  
    # Initialize the ChatGroq model
    chat = ChatGroq(
        temperature=0,
        groq_api_key=GROQ_API_KEY,
        model_name=GROQ_MODEL_NAME
    )

    def process_text_with_langchain(text_chunks):
        results = []
        for chunk in tqdm(text_chunks, desc="Processing Chunks", unit="chunk"):
            prompt = f"""
            Extract only important information from this text chunk and provide a concise output only, do not cut the payloads short, do not add anything else. DO NOT say 'Here is the extracted important information'
            ---
            {chunk}
            """
            response = chat.invoke(prompt)
            results.append(response.content.strip())
        return results

    # Read file content
    text_data = content
    # Split text strictly at '---'
    text_chunks = [chunk.strip() for chunk in text_data.split("---") if chunk.strip()]

    # Process through ChatGroq
    processed_results = process_text_with_langchain(text_chunks)

    # Join all results into one unified output
    final_output = "\n\n".join(processed_results)

    return final_output


def clean_sslscan_output(content):
    content = re.sub(r'\x1b\[[0-9;]*[mGK]', '', content)
    insights = {
        'server_info': {},
        'protocols': {},
        'security_features': {},
        'preferred_ciphers': {},
        'certificate': {}
    }

    # Extract server information
    server_match = re.search(r'Testing SSL server ([0-9.]+) on port (\d+)', content)
    if server_match:
        insights['server_info']['ip'] = server_match.group(1)
        insights['server_info']['port'] = server_match.group(2)

    # Extract protocol support
    protocol_matches = re.findall(r'(SSLv\d|TLSv\d\.\d)\s+(enabled|disabled)', content)
    for protocol, status in protocol_matches:
        insights['protocols'][protocol] = status

    # Extract security features
    tls_fallback = re.search(r'TLS Fallback SCSV:\s*(.+)', content)
    if tls_fallback and "supports" in tls_fallback.group(1):
        insights['security_features']['tls_fallback_scsv'] = True

    renegotiation = re.search(r'TLS renegotiation:\s*(.+)', content)
    if renegotiation and "supported" in renegotiation.group(1):
        insights['security_features']['secure_renegotiation'] = True

    compression = re.search(r'TLS Compression:\s*(.+)', content)
    if compression and "disabled" in compression.group(1):
        insights['security_features']['compression_disabled'] = True

    heartbleed_matches = re.findall(r'(TLSv\d\.\d) (not vulnerable|vulnerable) to heartbleed', content)
    insights['security_features']['heartbleed_status'] = {protocol: status for protocol, status in heartbleed_matches}

    # Extract preferred cipher information
    preferred_cipher_matches = re.findall(r'Preferred (TLSv\d\.\d)\s+\d+ bits\s+([^\s]+)', content)
    for protocol, cipher in preferred_cipher_matches:
        insights['preferred_ciphers'][protocol] = cipher

    # Extract certificate information
    key_strength = re.search(r'RSA Key Strength:\s+(\d+)', content)
    if key_strength:
        insights['certificate']['key_strength'] = key_strength.group(1)

    signature_algo = re.search(r'Signature Algorithm: (.+)', content)
    if signature_algo:
        insights['certificate']['signature_algorithm'] = signature_algo.group(1)

    subject = re.search(r'Subject:\s+(.+)', content)
    if subject:
        insights['certificate']['subject'] = subject.group(1)

    not_before = re.search(r'Not valid before: (.+) GMT', content)
    if not_before:
        insights['certificate']['not_valid_before'] = not_before.group(1)

    not_after = re.search(r'Not valid after:\s+(.+) GMT', content)
    if not_after:
        insights['certificate']['not_valid_after'] = not_after.group(1)
        # Parse the expiration date
        expiry_date = datetime.datetime.strptime(not_after.group(1), '%b %d %H:%M:%S %Y')
        current_date = datetime.datetime.now()
        days_to_expiry = (expiry_date - current_date).days
        insights['certificate']['days_to_expiry'] = days_to_expiry

    return json.dumps(insights, indent=2)

def clean_sslyze_output(content):
    content = json.loads(content)
    results = []

    for server in content.get("server_scan_results", []):
        info = {}
        server_loc = server.get("server_location", {})
        conn_result = server.get("connectivity_result", {})
        scan_result = server.get("scan_result", {})
        cert_info = scan_result.get("certificate_info", {}).get("result", {})
        chain = cert_info.get("certificate_deployments", [])[0].get("received_certificate_chain", [])

        # Server Info
        info["hostname"] = server_loc.get("hostname")
        info["ip_address"] = server_loc.get("ip_address")
        info["port"] = server_loc.get("port")

        # TLS Info
        info["tls_version"] = conn_result.get("highest_tls_version_supported")
        info["cipher_suite"] = conn_result.get("cipher_suite_supported")
        info["supports_ecdh"] = conn_result.get("supports_ecdh_key_exchange")
        info["client_auth"] = conn_result.get("client_auth_requirement")

        # Leaf Certificate Info
        if chain:
            leaf_cert = chain[0]
            info["leaf_common_name"] = leaf_cert.get("subject", {}).get("rfc4514_string")
            info["issuer"] = leaf_cert.get("issuer", {}).get("rfc4514_string")
            info["valid_from"] = leaf_cert.get("not_valid_before")
            info["valid_to"] = leaf_cert.get("not_valid_after")
            info["sha256_fingerprint"] = leaf_cert.get("fingerprint_sha256")
            info["key_algorithm"] = leaf_cert.get("public_key", {}).get("algorithm")
            info["key_size"] = leaf_cert.get("public_key", {}).get("key_size")

        results.append(info)

    return json.dumps(results, indent=2)

def clean_testssl_output(content):
    content = json.loads(content)
    result = {
        "host": None,
        "protocols": [],
        "deprecated_protocols": [],
        "ciphers": {
            "strong": [],
            "weak": [],
            "medium": [],
        },
        "certificate": {},
        "forward_secrecy": {},
        "server_config": {},
        "warnings": [],
        "info": []
    }

    scan = content["scanResult"][0]

    result["host"] = scan["targetHost"]

   # Protocols 
    for proto in scan.get("protocols", []):
        if proto["severity"] == "OK":
            result["protocols"].append(proto["id"])
        elif proto["severity"] == "LOW":
            result["deprecated_protocols"].append(proto["id"])

   # Ciphers 
    for cipher in scan.get("ciphers", []):
        finding = cipher.get("finding", "")
        severity = cipher.get("severity", "")
        if severity == "OK":
            result["ciphers"]["strong"].append(finding)
        elif severity == "MEDIUM":
            result["ciphers"]["medium"].append(finding)
        elif severity == "LOW":
            result["ciphers"]["weak"].append(finding)

   # Certificate 
    for entry in scan.get("serverDefaults", []):
        if "cert_commonName" in entry["id"]:
            result["certificate"]["CN"] = entry["finding"]
        elif "cert_notAfter" in entry["id"]:
            result["certificate"]["valid_until"] = entry["finding"]
        elif "cert_keySize" in entry["id"]:
            result["certificate"]["key_size"] = entry["finding"]
        elif "cert_signatureAlgorithm" in entry["id"]:
            result["certificate"]["signature_algo"] = entry["finding"]
        elif "cert_chain_of_trust" in entry["id"]:
            result["certificate"]["trust_chain"] = entry["finding"]
        elif "OCSP_stapling" in entry["id"]:
            result["certificate"]["ocsp_stapling"] = entry["finding"]

   # Forward Secrecy 
    for fs in scan.get("fs", []):
        if fs["id"] == "FS_KEMs":
            result["forward_secrecy"]["KEMs"] = fs["finding"]
        elif fs["id"] == "FS_ECDHE_curves":
            result["forward_secrecy"]["curves"] = fs["finding"]

   # Server Config 
    for pref in scan.get("serverPreferences", []):
        if "ALPN" in pref["id"]:
            result["server_config"]["ALPN"] = pref["finding"]
        elif "cipher_order-tls1_3" in pref["id"]:
            result["server_config"]["tls1.3_cipher_order"] = pref["finding"]

   # Warnings 
    for warn in content.get("clientProblem1", []):
        result["warnings"].append(warn["finding"])

    return json.dumps(result, indent=2)


def flatten_json(nested_json, parent_key='', sep='_'):
    """Recursively flattens a nested JSON object, excluding 'classifications'."""
    flattened = {}

    def _flatten(obj, key):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k != "classifications":
                    _flatten(v, f"{key}{sep}{k}" if key else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _flatten(v, f"{key}{sep}{i}" if key else str(i))
        else:
            flattened[key] = obj

    _flatten(nested_json, parent_key)
    return flattened

def chunk_dict(data, chunk_size=5):
    """Chunks a dictionary into smaller parts."""
    items = list(data.items())
    for i in range(0, len(items), chunk_size):
        yield dict(items[i:i + chunk_size])

def clean_wapiti_output(content):
    # Flatten and chunk
    flattened_json = flatten_json(content)
    chunks = list(chunk_dict(flattened_json, 5))

    # Initialize LLM
    chat = ChatGroq(
        temperature=0,
        groq_api_key=GROQ_API_KEY,
        model_name=GROQ_MODEL_NAME
    )

    # Process each chunk
    results = []
    for chunk in chunks:
        prompt = f"""
        Here is a JSON data chunk:
        {json.dumps(chunk, indent=2)}

        Extract only important information from this data and provide output in a readable format. STRICTLY Do not print things like Here is the output or let me know if you want more etc

        """
        response = chat.invoke(prompt)
        results.append(response.content)

    final_output = "\n".join(results)


    return final_output
    

def clean_dig_output(content):
    # Extract sections based on query types
    queries = re.split(r'; <<>> DiG .* <<>> ', content)[1:]  # Skip first empty split

    results = []

    for query in queries:
        result = {}

        # Extract query type and domain
        lines = query.strip().splitlines()
        query_info = lines[0].strip()
        result['Query'] = query_info

        # CNAME
        cname_match = re.search(r'www\.fakebook\.com\.\s+\d+\s+IN\s+CNAME\s+(\S+)', query)
        if cname_match:
            result['CNAME'] = cname_match.group(1)

        # A record
        a_match = re.search(r'fakebook\.com\.\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', query)
        if a_match:
            result['A Record (IP)'] = a_match.group(1)

        # SOA record
        soa_match = re.search(r'fakebook\.com\.\s+\d+\s+IN\s+SOA\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', query)
        if soa_match:
            result['SOA'] = {
                'Primary NS': soa_match.group(1),
                'Responsible Email': soa_match.group(2),
                'Serial': soa_match.group(3),
                'Refresh': soa_match.group(4),
                'Retry': soa_match.group(5),
                'Expire': soa_match.group(6),
                'Minimum TTL': soa_match.group(7),
            }

        # Query Time
        time_match = re.search(r';; Query time: (\d+) msec', query)
        if time_match:
            result['Query Time (ms)'] = time_match.group(1)

        # Timestamp
        when_match = re.search(r';; WHEN: (.+)', query)
        if when_match:
            result['Timestamp'] = when_match.group(1)

        # tb = "\n".join(results)

        results.append(result)

    return json.dumps(results, indent=2)

def clean_dnscan_output(content):
    insights = []

    # Extract domain name
    domain_match = re.search(r'\[\*\] Processing domain (\S+)', content)
    domain = domain_match.group(1) if domain_match else "Unknown domain"

    # 1. Nameservers
    nameservers = []
    ns_section = re.search(r'\[\+\] Getting nameservers\s+(.*?)\[', content, re.DOTALL)
    if ns_section:
        for line in ns_section.group(1).strip().split('\n'):
            if ' - ' in line:
                nameservers.append(line.strip())

    if nameservers:
        insights.append(f"1. NAMESERVERS: {domain} uses {len(nameservers)} nameservers: {', '.join(nameservers)}")

    # 2. Email provider from MX records
    mx_section = re.search(r'\[\+\] MX records found.*?\s+(.*?)(?:\[\*\])', content, re.DOTALL)
    if mx_section and 'outlook.com' in mx_section.group(1):
        insights.append("2. EMAIL: Using Microsoft Office 365 for email services")
    elif mx_section:
        insights.append(f"2. EMAIL: MX records found: {mx_section.group(1).strip()}")

    # 3. DMARC policy
    dmarc_section = re.search(r'\[\+\] DMARC records found\s+(.*?)(?:\[\+\]|\[\-\])', content, re.DOTALL)
    if dmarc_section:
        dmarc = dmarc_section.group(1).strip()
        if 'p=none' in dmarc:
            insights.append("3. SECURITY: DMARC configured but set to 'none' (monitoring only)")
        elif 'p=quarantine' in dmarc:
            insights.append("3. SECURITY: DMARC configured with 'quarantine' policy (medium protection)")
        elif 'p=reject' in dmarc:
            insights.append("3. SECURITY: DMARC configured with 'reject' policy (strong protection)")
        else:
            insights.append(f"3. SECURITY: DMARC configured: {dmarc}")

    # 4. DNSSEC status
    dnssec = re.search(r'DNSSEC (\w+)', content)
    if dnssec and 'not supported' in dnssec.group():
        insights.append("4. SECURITY: DNSSEC is not implemented (security vulnerability)")

    # 5. Key subdomains
    important_subdomains = []
    a_section = re.search(r'\[\*\] Scanning .* for A records\s+(.*?)(?:\[\+\]|\[\-\]|$)', content, re.DOTALL)
    if a_section:
        lines = a_section.group(1).strip().split('\n')
        for line in lines:
            if ' - ' in line:
                _, subdomain = line.split(' - ', 1)
                subdomain = subdomain.strip()
                key_types = ['www', 'mail', 'lms', 'elearning', 'connect', 'alumni']
                for key in key_types:
                    if subdomain.startswith(f"{key}."):
                        important_subdomains.append(subdomain)
                        break

    if important_subdomains:
        insights.append(f"5. WEB PRESENCE: Key subdomains: {', '.join(important_subdomains[:5])}")

    # 6. Cloud services
    cloud_services = []
    txt_section = re.search(r'\[\+\] TXT records found\s+(.*?)(?:\[\+\]|\[\-\])', content, re.DOTALL)
    if txt_section:
        txt_content = txt_section.group(1).lower()
        if 'google' in txt_content:
            cloud_services.append('Google services')
        if 'amazon' in txt_content or 'aws' in txt_content:
            cloud_services.append('Amazon services')
        if 'salesforce' in txt_content or 'pardot' in txt_content:
            cloud_services.append('Salesforce/Pardot')
        if 'office' in txt_content or 'microsoft' in txt_content:
            cloud_services.append('Microsoft services')

    if cloud_services:
        insights.append(f"6. CLOUD SERVICES: Integrations with {', '.join(cloud_services)}")

    # 7. SPF record existence (email security)
    if txt_section and 'v=spf1' in txt_section.group(1):
        insights.append("7. EMAIL SECURITY: SPF record is configured (helps prevent email spoofing)")

    return insights

def remove_ansi_dnsenum(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def clean_dnsenum_output(content):
    data = {}

    # Target domain
    match_domain = re.search(r"-----\s+(.*?)\s+-----", content)
    data['Target Domain'] = match_domain.group(1) if match_domain else "N/A"

    # Host address
    match_host = re.search(rf"{re.escape(data['Target Domain'])}\.\s+\d+\s+IN\s+A\s+([\d.]+)", content)
    data['Host Address'] = match_host.group(1) if match_host else "N/A"

    # Wildcard DNS detection
    wildcard_match = re.search(r"Wildcards detected.*?subdomains will point to the same IP address", content, re.DOTALL)
    if wildcard_match:
        subdomain_ip_match = re.search(r"(\S+)\.fakebook\.com\.\s+\d+\s+IN\s+A\s+([\d.]+)", content)
        data['Wildcard Subdomain'] = subdomain_ip_match.group(1) if subdomain_ip_match else "N/A"
        data['Wildcard IP'] = subdomain_ip_match.group(2) if subdomain_ip_match else "N/A"
    else:
        data['Wildcard Subdomain'] = data['Wildcard IP'] = "None"

    # Name server
    ns_match = re.search(r"Name Servers:.*?(\S+)\s+\d+\s+IN\s+A\s+([\d.]+)", content, re.DOTALL)
    data['Name Server'] = f"{ns_match.group(1)} → {ns_match.group(2)}" if ns_match else "N/A"

    # MX records
    mx_match = re.search(r"Mail \(MX\) Servers:.*?(\S+)\s+\d+\s+IN\s+CNAME\s+(\S+)\.\n\2\.\s+\d+\s+IN\s+A\s+([\d.]+)", content, re.DOTALL)
    if mx_match:
        data['Mail Server'] = f"{mx_match.group(1)} (CNAME → {mx_match.group(2)} → {mx_match.group(3)})"
    else:
        data['Mail Server'] = "N/A"

    # Zone transfer attempts
    zt_matches = re.findall(r"Trying Zone Transfer for .*? on (\S+)", content)
    data['Zone Transfer Attempts'] = zt_matches if zt_matches else []

    # Brute-forced subdomains
    subdomains = re.findall(r"(\S+\.fakebook\.com)\.\s+\d+\s+IN\s+(?:CNAME|A)\s+\S+", content)
    data['Subdomains Found'] = subdomains

    # IP ranges
    # IP ranges
# IP ranges
    class_c = re.search(r"class C netranges:\s+[_\s]*([\d./]+)", content)
    data['Class C Netrange'] = class_c.group(1) if class_c else "N/A"

    ip_block = re.search(r"ip blocks:\s+[_\s]*([\d./]+)", content)
    data['IP Block'] = ip_block.group(1) if ip_block else "N/A"

    return json.dumps(data, indent=2)

def clean_dnsrecon_output(content):
    important_info = []

    # Domain name
    if "Enumeration against:" in content:
        domain = content.split("Enumeration against:")[1].split("...")[0].strip()
        important_info.append(f"Domain: {domain}")

    # DNSSEC status
    if "DNSSEC is not configured" in content:
        important_info.append("Security: DNSSEC not configured")

    # NS servers (just count them)
    ns_count = content.count(" NS ")
    if ns_count > 0:
        servers = set()
        for line in content.split("\n"):
            if " NS " in line:
                server = line.split(" NS ")[1].split()[0]
                servers.add(server)
        important_info.append(f"Name Servers: {', '.join(servers)}")

    # Check for BIND version
    if "Bind Version" in content:
        bind_version = content.split("Bind Version for")[1].split('"')[1]
        important_info.append(f"BIND Version: {bind_version}")

    # IP addresses
    if " A " in content:
        for line in content.split("\n"):
            if " A fakebook.com " in line:
                ip = line.split()[-1]
                important_info.append(f"Main IP: {ip}")
                break

    # Mail server
    if " MX " in content:
        for line in content.split("\n"):
            if " MX " in line:
                mail_server = line.split(" MX ")[1].split()[0]
                important_info.append(f"Mail Server: {mail_server}")
                break

    return "\n".join(important_info)


# === Tool-Specific Cleaner Functions ===

def clean_gobuster_output(content: str):
    structured_data = []
    for line in content.strip().split("\n"):
        status_match = re.search(r'\(Status:\s(\d+)\)', line)
        url_match = re.search(r'\[-->\s(.*?)\]', line)
        if not url_match:
            continue
        url = url_match.group(1)
        status = status_match.group(1) if status_match else "Unknown"
        structured_data.append({"URL": url, "Status": status})
    return json.dumps(structured_data, indent=2)

def clean_ffuf_output(content: str):
    try:
        data = json.loads(content)
        
        # Extract and format the desired data
        cleaned = [
            {"URL": item["url"], "Status": item.get("status", "Unknown")}
            for item in data.get("results", [])
            if "url" in item
        ]
        
        # Return it as a pretty-printed JSON string
        return json.dumps(cleaned, indent=2)
    except json.JSONDecodeError:
        print("[ERROR] Failed to parse FFUF output as JSON")
        return json.dumps([])

def clean_wfuzz_output(content: str):
    try:
        data = json.loads(content)
        if not isinstance(data, list):
            print("[ERROR] WFUZZ data is not a list")
            return json.dumps([])
            
        return json.dumps([
            {"URL": item["url"], "Status": item.get("code", "Unknown")}
            for item in data if "url" in item
        ], indent=2)
    except json.JSONDecodeError:
        print("[ERROR] Failed to parse WFUZZ output as JSON")
        return json.dumps([])

def clean_dirsearch_output(content: str):
    try:
        # Use StringIO to read the CSV content from a string instead of a file
        df = pd.read_csv(StringIO(content))
       
        # Try to normalize column names
        df.columns = [col.strip().lower() for col in df.columns]
       
        if "url" in df.columns:
            url_col = "url"
        elif "path" in df.columns:
            url_col = "path"
        else:
            return json.dumps([])  # No usable URL column, return empty
            
        df = df.rename(columns={url_col: "URL"})  # Standardize the column name
        
        if "status" in df.columns:
            df = df.rename(columns={"status": "Status"})
        else:
            df["Status"] = "Unknown"
            
        df = df[["URL", "Status"]].dropna(subset=["URL"])
        return json.dumps(df.to_dict(orient="records"), indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to process dirsearch CSV: {str(e)}")
        
        # Try parsing directly from the error string if it contains CSV content
        if "URL,Status" in str(e) and "\n" in str(e):
            try:
                # Extract the actual CSV content from the error message
                csv_content = str(e).split("No such file or directory: '")[1].split("'")[0]
                return clean_dirsearch_output(csv_content)
            except Exception as inner_e:
                print(f"[ERROR] Failed secondary parse attempt: {str(inner_e)}")
                
        return json.dumps([])



def clean_generic_output(content):
    """Generic cleaning function for any tool output"""
    # Remove ANSI color codes
    content = re.sub(r'\x1b\[[0-9;]*m', '', content)
    
    # Remove any redundant whitespace
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    
    return "\n".join(lines)

def generate_module_report(module, module_reports, chat_model, token):
    "Generate a consolidated report for a specific module."
    # Join all the cleaned reports for this module
    combined_text = "\n\n--- Next Tool Output ---\n\n".join(module_reports)

    # Get the module-specific template
    template = MODULE_TEMPLATES.get(module, MODULE_TEMPLATES["Misc"])

    
    
    if module == "Pathfinders":
        # Parse cleaned JSON reports from all pathfinder tools
        all_entries = []
        for report in module_reports:
            try:
                if isinstance(report, str):
                    parsed = json.loads(report)
                    if isinstance(parsed, list):
                        all_entries.extend(parsed)
                else:
                    all_entries.extend(report)
            except json.JSONDecodeError:
                continue

        # Deduplicate based on normalized URL
        seen = set()
        deduped = []
        for entry in all_entries:
            url = entry["URL"].rstrip("/").replace("www.", "")
            if url not in seen:
                seen.add(url)
                deduped.append(entry)

        # Save cleaned entries for access later
        filename = os.path.join("uploaded_files", f"module_report_all_{module}_{token}.json")
        with open(filename, "w") as f:
            json.dump(deduped, f, indent=2)

        # Generate summary of valid (status 200) paths
        valid_200 = [e["URL"] for e in deduped if str(e.get("Status")) == "200"]
        display = valid_200[:15]
        extra = "..." if len(valid_200) > 15 else ""

        result = "## Pathfinders Valid Paths\n\nThe valid paths include:\n\n"
        result += "\n".join(f"- {p}" for p in display)
        if extra:
            result += "\n- " + extra
        return result
    
    elif module == "Assetfinder":
        all_targets = set()
        all_params = set()

        for report in module_reports:
            lines = report.strip().splitlines()
            for raw_line in lines:
                # Split on commas, trim parts
                parts = [part.strip() for part in raw_line.split(",") if part.strip()]
                for item in parts:
                    if is_param(item):
                        all_params.add(item)
                    elif is_target(item):
                        all_targets.add(item)
                    # else: ignore invalid

        result_dict = {
            "targets": sorted(all_targets),
            "params": sorted(all_params)
        }

        filename = os.path.join("uploaded_files", f"module_report_all_{module}_{token}.json")
        with open(filename, "w") as f:
            json.dump(result_dict, f, indent=2)

        summary = f"## {module} Security Assessment\n\n"

        if result_dict["targets"]:
            summary += "### Targets\n\n" + "\n".join(f"- {t}" for t in result_dict["targets"][:5])
            if len(result_dict["targets"]) > 5:
                summary += "\n- ..."
            summary += "\n\n"

        if result_dict["params"]:
            summary += "### Parameters\n\n" + "\n".join(f"- {p}" for p in result_dict["params"][:5])
            if len(result_dict["params"]) > 5:
                summary += "\n- ..."

        if not result_dict["targets"] and not result_dict["params"]:
            summary += "_No valid targets or parameters found._"

        return summary
    
    
    elif module in ["SQLi", "WebScanner", "Misc"]:
        return f"## {module} Security Assessment\n\n" + "\n\n".join(module_reports)
    else:
        # Create the prompt
        prompt_text = template.format(text=combined_text)
        
        # Get response from the chat model
        response = chat_model.invoke(prompt_text)
        return f"## {module} Security Assessment\n\n{response.content}"
        

def append_module_report(consolidated_report, module, module_content):
    """Append a module report to the consolidated report"""
    if not consolidated_report:
        header = "# Security Assessment Report\n\n"
        consolidated_report = header
    
    # Add a separator if this isn't the first module
    if consolidated_report.strip() != "# Security Assessment Report":
        consolidated_report += "\n\n" + "-" * 80 + "\n\n"
    
    # Add the module content
    consolidated_report += module_content
    
    return consolidated_report

def process_tool_report(tool_name, content):
    if tool_name == "Nmap":
        return process_nmap_chunked(content)

    cleaner_name = TOOL_CLEANERS.get(tool_name, "clean_generic_output")
    cleaner_func = globals().get(cleaner_name, clean_generic_output)
    return cleaner_func(content)