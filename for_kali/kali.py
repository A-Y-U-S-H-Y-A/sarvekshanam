from flask import Flask, request, jsonify
import subprocess
import threading
import requests
import os
import re
from collections import defaultdict
from dotenv import load_dotenv
import threading
import json

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)

CALLBACK_URL = os.getenv("WINDOWS_CALLBACK")

def get_fallback_file(filename):
    if filename.endswith('.json'):
        return '{}'
    elif filename.endswith('.xml'):
        return '<?xml version="1.0" encoding="UTF-8"?><result>No data</result>'
    else:
        return '-'

def modify_url_for_xsser(url):
    return re.sub(r'(?<=\=)[^&]*', 'XSS', url)


class Tool:
    def __init__(self, name, command_template, modules, output_filename=None):
        self.name = name
        self.command_template = command_template
        self.modules = modules
        self.output_filename = output_filename
    
    def to_dict(self):
        return {
            "name": self.name,
            "command_template": self.command_template,
            "modules": self.modules,
            "output_filename": self.output_filename
        }

    def run(self, url, token):
        output_file = None
        try:
            domain = re.sub(r'^https?://(www\.)?', '', url).split('/')[0]
            fuzz_url = url
            if self.name.lower() == "wfuzz":
                fuzz_url = url.rstrip('/') + '/FUZZ'
            
            formatted_cmd = self.command_template.format(
                url=url,
                domain=domain,
                token=token,
                xsser_url=modify_url_for_xsser(url),
                fuzz_url=fuzz_url
            )

            if self.output_filename:
                output_file = self.output_filename.format(token=token, url=url, domain=domain)
            elif '>' in formatted_cmd:
                output_file = formatted_cmd.split('>')[-1].strip()

            if self.name.lower() == "sqlmap":
                timeout = 300
            elif self.name.lower() in ["wapiti", "nmap", "fierce", "dnsenum", "sslscan", "sslyze", "testssl", "sublist3r", "assetfinder", "arjun"]:
                timeout = None
            else:
                timeout = 60

            subprocess.run(formatted_cmd, shell=True, timeout=timeout)

            if self.name.lower() == "sqlmap":
                log_path = os.path.expanduser(f"~/.local/share/sqlmap/output/{domain}/log")
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        content = f.read()
                        if content.strip():
                            return f"sqlmap_{token}.txt", content
                return f"sqlmap_{token}.txt", "No SQLi Found"

            elif output_file and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return os.path.basename(output_file), f.read()

        except subprocess.TimeoutExpired:
            print(f"{self.name} timed out")
            if output_file:
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            return os.path.basename(output_file), f.read()
                    except Exception as e:
                        print(f"Error reading output file after timeout: {str(e)}")
                else:
                    return os.path.basename(output_file), "No output generated (tool timed out or failed)"
        except Exception as e:
            print(f"Error running {self.name}: {str(e)}")
            if output_file and os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        return os.path.basename(output_file), f.read()
                except Exception as read_err:
                    print(f"Error reading output file after error: {str(read_err)}")

        return None, None

class ToolManager:
    def __init__(self):
        self.tools = []

    def register_tool(self, name, command_template, modules, output_filename=None):
        self.tools.append(Tool(name, command_template, modules, output_filename))

    def get_tools_by_modules(self, modules):
        selected = []
        for tool in self.tools:
            if any(m in tool.modules for m in modules):
                selected.append(tool)
        return selected
    
    def load_tools_from_json(self, filepath):
        with open(filepath, "r") as f:
            tools_data = json.load(f)
            for tool in tools_data:
                self.register_tool(
                    tool["name"],
                    tool["command_template"],
                    tool["modules"],
                    tool.get("output_filename")  # Use .get() to avoid KeyError if it's missing
                )
    
    def get_tools_grouped_by_category(self):
        categorized_tools = defaultdict(list)
        for tool in self.tools:
            for module in tool.modules:
                categorized_tools[module].append(tool.to_dict())
        return categorized_tools

tool_manager = ToolManager()
tool_manager.load_tools_from_json("tools.json")

# tool_manager.register_tool("Photon", 'photon -u {domain} -e json && cp {domain}/exported.json photon_{token}.json', ["Pathfinders"], output_filename="photon_{token}.json")


# Global counter for tracking reports
class ReportCounter:
    def __init__(self, total):
        self.remaining = total
        self.lock = threading.Lock()

    def decrement(self):
        with self.lock:
            self.remaining -= 1
            return self.remaining

def send_tool_result(tool_name, module, token, filename, content, counter):
    if not filename:
        filename = f"{tool_name.lower()}_{token}.txt"
    
    if not content or not content.strip():
        print(f"No results for {tool_name}, sending fallback content.")
        content = get_fallback_file(filename)
        

    reports_left = counter.decrement()

    callback_data = {
        "token": token,
        "tool": tool_name,
        "module": module,
        "files": {filename: content},
        "reports_left": reports_left
    }

    try:
        response = requests.post(CALLBACK_URL, json=callback_data)
        print(f"Callback for {tool_name} response: {response.status_code}, reports left: {reports_left}")
        if response.status_code == 200:
            # Delete the file if it exists and send was successful
            if os.path.exists(filename):
                os.remove(filename)
                print(f"Deleted file: {filename}")
    except Exception as e:
        print(f"Callback error for {tool_name}: {str(e)}")

def run_tool(tool, url, token, counter):
    module = tool.modules[0]
    filename, content = tool.run(url, token)
    send_tool_result(tool.name, module, token, filename, content, counter)

def run_commands(url, modules, token):
    tools_to_run = tool_manager.get_tools_by_modules(modules)
    counter = ReportCounter(len(tools_to_run))
    threads = []
    for tool in tools_to_run:
        thread = threading.Thread(target=run_tool, args=(tool, url, token, counter))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "OK"}), 200

@app.route("/tools", methods=["GET"])
def get_all_tools():
    categorized_tools = tool_manager.get_tools_grouped_by_category()
    return jsonify(categorized_tools)

@app.route("/", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        url = data.get("URL")
        modules = data.get("MODULES", [])
        token = data.get("Token")
        print(data)

        if not url or not token or not isinstance(modules, list):
            return jsonify({"error": "Invalid request format"}), 400

        thread = threading.Thread(target=run_commands, args=(url, modules, token))
        thread.start()

        return jsonify({"status": "Processing started"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="192.168.31.53", port=5000)
