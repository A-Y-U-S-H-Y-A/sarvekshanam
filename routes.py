from flask import render_template, request, jsonify, make_response, send_file, redirect, url_for, session
import os
import re
import json
import sqlite3
from config import UPLOAD_FOLDER, DIR 
from chatbot import get_chat_response, chat, reset_chat_context,get_chat_qna, generate_initial_context
from report_processor import process_tool_report, generate_module_report, append_module_report
from kali import tool_manager  # Add this near the top if not already present
import requests
from urllib.parse import urlparse
import uuid
from config import GROQ_API_KEY, GROQ_MODEL_NAME, TEMPERATURE
import re

# SQLite database setup
DB_PATH = os.path.join(DIR, 'file_tracker.db')

def process_services_and_get_modules(services_json):
    """
    Extract all unique module names from services and return a list.
    """
    all_modules = set()
    for tool in services_json:
        modules = tool.get("modules", [])
        all_modules.update(modules)
    return list(all_modules)

def fetch_services_from_endpoint(remote_endpoint):
    """
    Try to fetch services (tools) from the remote endpoint's /tools route.
    Returns a tuple: (services_json, error_string_or_None)
    """
    try:
        response = requests.get(f"{remote_endpoint}/tools")
        if response.status_code == 200:
            return response.json(), None
        else:
            return None, "Remote endpoint is not available"
    except requests.RequestException as e:
        return None, f"Failed to connect to remote endpoint: {str(e)}"


def init_db():
    """Initialize the SQLite database if it doesn't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table to track file processing statistics
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_stats (
        token TEXT PRIMARY KEY,
        files_processed INTEGER DEFAULT 0,
        total_files INTEGER DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS remote_endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint TEXT UNIQUE,
        last_used BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()


def register_routes(app):
    """Register all routes with the Flask app"""
    
    # Initialize the database
    init_db()
    
    # Dictionary to keep track of received files and their modules for each token
    tool_report_tracker = {}
    
    @app.route('/session-data')
    def get_session_data():
        if 'auth_token' in session and 'url' in session and 'modules' in session:
            return jsonify({
                "auth_token": session["auth_token"],
                "url": session["url"],
                "modules": session["modules"]
            })
        return jsonify({"error": "No session data"}), 404
    
    # Create Route to get remote enpoint from session
    @app.route('/get_remote_endpoint', methods=['GET'])
    def get_remote_endpoint():
        remote_endpoint = session.get("remote_endpoint")
        
        if not remote_endpoint:
            return jsonify({"error": "No remote endpoint set"}), 400
        
        return jsonify({"remote_endpoint": remote_endpoint}), 200

    @app.route('/list_remote_endpoints', methods=['GET'])
    def list_remote_endpoints():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT endpoint, last_used, created_at FROM remote_endpoints ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()

        return jsonify({
            "endpoints": [
                {
                    "endpoint": row["endpoint"],
                    "last_used": bool(row["last_used"]),
                    "created_at": row["created_at"]
                } for row in rows
            ]
        }), 200

    @app.route('/delete_remote_endpoint', methods=['POST'])
    def delete_remote_endpoint():
        data = request.get_json()
        endpoint_to_delete = data.get("remote_endpoint")

        if not endpoint_to_delete:
            return jsonify({"error": "Missing remote_endpoint in request"}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Check if it exists
        cursor.execute("SELECT * FROM remote_endpoints WHERE endpoint = ?", (endpoint_to_delete,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Endpoint not found"}), 404

        # If it was the last used one, clear session and reassign another as last_used
        cursor.execute("SELECT last_used FROM remote_endpoints WHERE endpoint = ?", (endpoint_to_delete,))
        last_used = cursor.fetchone()[0]
        cursor.execute("DELETE FROM remote_endpoints WHERE endpoint = ?", (endpoint_to_delete,))
        
        if last_used:
            # Assign another as last used, if any
            cursor.execute("SELECT endpoint FROM remote_endpoints ORDER BY created_at DESC LIMIT 1")
            new_last = cursor.fetchone()
            if new_last:
                cursor.execute("UPDATE remote_endpoints SET last_used = 1 WHERE endpoint = ?", (new_last[0],))
                session["remote_endpoint"] = new_last[0]
            else:
                session.pop("remote_endpoint", None)

        conn.commit()
        conn.close()

        return jsonify({"message": "Endpoint deleted successfully"}), 200


    # Create Route to store remote enpoint in session
    @app.route('/set_remote_endpoint', methods=['POST'])
    def set_remote_endpoint():
        data = request.get_json()
        remote_endpoint = data.get("remote_endpoint")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if not remote_endpoint:
            # Use last used one if not provided
            cursor.execute("SELECT endpoint FROM remote_endpoints WHERE last_used = 1 ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "No remote endpoint provided and no previous one found"}), 400
            session["remote_endpoint"] = row[0]
            return jsonify({"message": "Using last used endpoint", "remote_endpoint": row[0]}), 200

        # Clean and validate
        remote_endpoint = remote_endpoint.rstrip('/')
        URL_REGEX = re.compile(
            r'^(http:\/\/|https:\/\/)?'
            r'(([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?)|(\d{1,3}(\.\d{1,3}){3}))'
            r'(:\d{1,5})?'
            r'(\/.*)?$'
        )
        if not URL_REGEX.match(remote_endpoint):
            conn.close()
            return jsonify({"error": "Invalid remote endpoint format"}), 400

        parsed = urlparse(remote_endpoint)
        if not parsed.scheme:
            remote_endpoint = f"http://{remote_endpoint}"

        # Update DB
        cursor.execute("UPDATE remote_endpoints SET last_used = 0")
        cursor.execute("INSERT OR IGNORE INTO remote_endpoints (endpoint, last_used) VALUES (?, 1)", (remote_endpoint,))
        cursor.execute("UPDATE remote_endpoints SET last_used = 1 WHERE endpoint = ?", (remote_endpoint,))
        conn.commit()
        conn.close()
        
        services, error = fetch_services_from_endpoint(remote_endpoint)
        if error:
            return jsonify({"error": f"Remote endpoint set, but service fetch failed: {error}"}), 500

        unique_modules = process_services_and_get_modules(services)
        session["tools"] = ", ".join(sorted(set(unique_modules)))

        reset_chat_context(context=session.get("tools"))


        session["remote_endpoint"] = remote_endpoint
        return jsonify({"message": "Remote endpoint set successfully", "remote_endpoint": remote_endpoint}), 200


    # Create a route to check if the enpoint is available. This can be done by sending a simple GET request to /health which will give a json response
    @app.route('/check_remote_endpoint', methods=['GET'])
    def check_remote_endpoint():
        remote_endpoint = session.get("remote_endpoint")
        
        if not remote_endpoint:
            return jsonify({"error": "No remote endpoint set"}), 400
        
        try:
            response = requests.get(f"{remote_endpoint}/health")
            if response.status_code == 200:
                return jsonify({"message": "Remote endpoint is available"}), 200
            else:
                return jsonify({"error": "Remote endpoint is not available"}), 503
        except requests.RequestException as e:
            return jsonify({"error": f"Failed to connect to remote endpoint: {str(e)}"}), 500
        
    # Create a route to check the services offered by the remote endpoint. This can be done by sending a simple GET request to /tools which will give a json response
    @app.route('/check_services', methods=['GET'])
    def check_services():
        remote_endpoint = session.get("remote_endpoint")
        
        if not remote_endpoint:
            return jsonify({"error": "No remote endpoint set"}), 400

        services, error = fetch_services_from_endpoint(remote_endpoint)
        if error:
            return jsonify({"error": error}), 503

        return jsonify({
            "message": "Remote endpoint is available",
            "services": services
        }), 200


    @app.route("/start_attack", methods=["POST"])
    def start_attack():
        data = request.get_json()
        url = data.get("url")
        modules = data.get("modules")

        if not url or not modules or not session.get("remote_endpoint"):
            return jsonify({"error": "Missing URL or modules or endpoint"}), 400

        
        token = str(uuid.uuid4())
        try:
            requests.post(session["remote_endpoint"], json={
                "Auth": "Valid",
                "URL": url,
                "Token": token,
                "MODULES": modules
            })
        except Exception as e:
            return jsonify({"error": f"Failed to send to remote: {str(e)}"}), 500

        # Save to session
        session["auth_token"] = token
        session["url"] = url
        session["modules"] = modules

        return jsonify({
            "message": "Attack initiated",
            "auth_token": token,
            "url": url,
            "modules": modules
        })


    @app.route("/file_categories", methods=["GET"])
    def file_categories():
        """Return categorized files by tool name for a specific token"""
        auth_token = session.get("auth_token")
        if not auth_token:
            return jsonify({"error": "Unauthorized - No auth token provided"}), 401
        
        # Get the full path to the uploaded files directory
        upload_dir = os.path.join(DIR, UPLOAD_FOLDER)
        
        # List all files in the directory
        all_files = os.listdir(upload_dir)
        
        # Filter files that belong to this token
        token_files = [f for f in all_files if str(auth_token) in f]
        
        meta_path = os.path.join(DIR, 'session_meta', f"{auth_token}.json")
        if not os.path.exists(meta_path):
            return jsonify({"error": "No metadata found for this session"}), 404

        with open(meta_path, "r") as f:
            meta = json.load(f)

        # Define tool names and their categories based on registration code
        tool_categories = meta.get("tool_categories", {})
        
        # Define filename patterns for each tool based on the registration commands
        tool_filename_patterns = meta.get("tool_filename_patterns", {})
        
        # Initialize result structure
        result = {}
        
        # Initialize categories
        for category in tool_categories:
            result[category] = {}
            # Add empty module_reports key for each category
            result[category]["module_reports"] = None
            result[category]["module_reports_all"] = None
        
        # Process each file
        for file in token_files:
            # Check for the main report file
            if file.startswith("report_") and str(auth_token) in file:
                result["report"] = file
                continue
            
            # Combined check for module reports
            if file.startswith("module_report_") and str(auth_token) in file:
                parts = file.split('_')
                if len(parts) >= 3:
                    # Determine if it's an "all" report or a regular one
                    if "all" in parts:
                        # For module_report_all_Pathfinders_* format
                        all_index = parts.index("all")
                        if len(parts) > all_index + 1:
                            module_name = parts[all_index + 1]
                            report_key = "module_reports_all"
                        else:
                            continue  # Invalid format
                    else:
                        module_name = parts[2]
                        report_key = "module_reports"
                    
                    # Match module to category
                    for category in result:
                        if category.lower() == module_name.lower():
                            result[category][report_key] = file
                            break
                    continue  # Skip further processing for this file
            
            # Try to match the file to a specific tool based on filename patterns
            matched_tool = None
            matched_category = None
            
            for tool, pattern in tool_filename_patterns.items():
                if pattern.lower() in file.lower():
                    matched_tool = tool
                    # Find the category for this tool
                    for category, tools in tool_categories.items():
                        if tool in tools:
                            matched_category = category
                            break
                    break
            
            # If no match, check if it's a cleaned file
            if not matched_tool and file.startswith("cleaned_"):
                original_file = file[8:]  # Remove "cleaned_" prefix
                # Try to match the original file name
                for tool, pattern in tool_filename_patterns.items():
                    if pattern.lower() in original_file.lower():
                        matched_tool = tool
                        # Find the category for this tool
                        for category, tools in tool_categories.items():
                            if tool in tools:
                                matched_category = category
                                break
                        break
            
            # If still no match, put in Misc category
            if not matched_category:
                matched_category = "Misc"
                matched_tool = "Unknown"
            
            # Initialize tool entry if it doesn't exist
            if matched_category not in result:
                result[matched_category] = {}
            
            if matched_tool not in result[matched_category]:
                result[matched_category][matched_tool] = []
            
            # Add file to the tool's file list
            result[matched_category][matched_tool].append(file)
        
        return jsonify(result)



    @app.route("/")
    def index():
        return render_template('chat.html')
    
    @app.route("/dashboard")
    def see_db():
        return render_template('index.html')
    
    @app.route("/new")
    def new_chat():
        """Clear all context and refresh all chats"""
        # Reset the chat context in the chatbot module
        reset_chat_context(context=session.get("tools"))
        
        # Clear the session
        session.clear()
        
        return redirect(url_for('index'))
    
    @app.route("/check", methods=["GET"])
    def check():
        auth_token = session.get("auth_token")
        if not auth_token:
            return "Unauthorized", 401
        
        # Include the uploaded_files directory in the path
        file_path = os.path.join(DIR, UPLOAD_FOLDER, f"report_{auth_token}.txt")
        
        if os.path.exists(file_path):
            session["report_ready"] = True
            return send_file(file_path, mimetype="text/plain")
        else:
            return "wait", 200
    


    @app.route('/callback', methods=['POST'])
    def callback():
        data = request.json
        files = data.get("files", {})
        token = data.get("token", "No Token Provided")
        tool_name = data.get("tool", "Unknown Tool")
        module = data.get("module", "Unknown Module")
        reports_left = data.get("reports_left", -1)

        print(f"[CALLBACK] token={token}, tool={tool_name}, module={module}, reports_left={reports_left}")

        # DB update
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM file_stats WHERE token = ?', (token,))
        record = cursor.fetchone()

        if record:
            cursor.execute('''
                UPDATE file_stats 
                SET files_processed = files_processed + ?, 
                    total_files = ? 
                WHERE token = ?
            ''', (len(files), reports_left + len(files), token))
        else:
            cursor.execute('''
                INSERT INTO file_stats (token, files_processed, total_files)
                VALUES (?, ?, ?)
            ''', (token, len(files), reports_left + len(files)))

        conn.commit()
        conn.close()

        # Init token tracker if not present
        if token not in tool_report_tracker:
            tool_report_tracker[token] = {
                "modules": {},
                "final_report_path": os.path.join(UPLOAD_FOLDER, f"report_{token}.txt"),
                "module_reports": []
            }

        if module not in tool_report_tracker[token]["modules"]:
            tool_report_tracker[token]["modules"][module] = {
                "tools_received": [],
                "all_received": False
            }
        tfname = ""
        # Save and process files
        for filename, content in files.items():
            tfname = filename
            original_file_path = os.path.join(UPLOAD_FOLDER, filename)
            with open(original_file_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Cleaned file path
            cleaned_file_path = os.path.join(UPLOAD_FOLDER, f"cleaned_{filename}")
            
            # Check if content is fallback/empty
            is_fallback = False
            content_trimmed = content.strip()
            
            if content_trimmed in ["-", "{}", '<?xml version="1.0" encoding="UTF-8"?><result>No data</result>']:
                is_fallback = True
            elif not content_trimmed:
                is_fallback = True
            
            if is_fallback:
                print(f"[SKIP] {tool_name} returned fallback or empty content. Logging as processed anyway.")
                
                # Save empty file
                with open(cleaned_file_path, "w", encoding="utf-8") as f:
                    f.write(content_trimmed)
                
                # Still count it toward received tools
                tool_report_tracker[token]["modules"][module]["tools_received"].append({
                    "tool": tool_name,
                    "original_file": original_file_path,
                    "cleaned_file": cleaned_file_path,
                    "empty": True  # You can use this flag later if needed
                })
            else:
                processed_content = process_tool_report(tool_name, content)
                if isinstance(processed_content, list):
                    processed_content = '\n'.join(processed_content)
                with open(cleaned_file_path, "w", encoding="utf-8") as f:
                    f.write(processed_content)

                tool_report_tracker[token]["modules"][module]["tools_received"].append({
                    "tool": tool_name,
                    "original_file": original_file_path,
                    "cleaned_file": cleaned_file_path,
                    "empty": False
                })

            print(f"[PROCESSED] {tool_name} from module {module}")



        # Check if all tools for this module are done
        expected_tool_count = len(tool_manager.get_tools_by_modules([module]))
        received_tool_count = len(tool_report_tracker[token]["modules"][module]["tools_received"])
        print(f"[CHECK] {module}: Received {received_tool_count} / Expected {expected_tool_count}")

        if received_tool_count >= expected_tool_count:
            tool_report_tracker[token]["modules"][module]["all_received"] = True

            # Generate module report
            module_reports = []
            for tool_info in tool_report_tracker[token]["modules"][module]["tools_received"]:
                with open(tool_info["cleaned_file"], "r", encoding="utf-8") as f:
                    module_reports.append(f.read())

            module_report = generate_module_report(module, module_reports, chat, token)
            module_report_path = os.path.join(UPLOAD_FOLDER, f"module_report_{module}_{token}.txt")
            with open(module_report_path, "w", encoding="utf-8") as f:
                f.write(module_report)

            tool_report_tracker[token]["module_reports"].append({
                "module": module,
                "path": module_report_path
            })

            print(f"[MODULE REPORT] Generated for {module}")

        # Check if all modules are done
        all_modules_done = all(info["all_received"] for info in tool_report_tracker[token]["modules"].values())
        if all_modules_done:
            combined_report = ""
            for report_info in tool_report_tracker[token]["module_reports"]:
                with open(report_info["path"], "r", encoding="utf-8") as f:
                    module_content = f.read()
                combined_report = append_module_report(combined_report, report_info["module"], module_content)
            from chatbot import current_context
            with open(tool_report_tracker[token]["final_report_path"], "w", encoding="utf-8") as f:
                f.write(combined_report)

            print(f"[FINAL REPORT] Generated for token {token}")
            from chatbot import set_context
            with open(tool_report_tracker[token]["final_report_path"], "r", encoding="utf-8") as f:
                report_text = f.read()
            
            set_context(f"\n Answer Questions with respect to this report:\n{report_text}")
        
        # For the file categories endpoint
        SESSION_META_DIR = os.path.join(DIR, 'session_meta')
        os.makedirs(SESSION_META_DIR, exist_ok=True)

        meta_path = os.path.join(SESSION_META_DIR, f"{token}.json")

        # Load existing or initialize
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
        else:
            meta = {
                "tool_categories": {},
                "tool_filename_patterns": {}
            }

        # Update pattern and categories

        base_name = os.path.splitext(filename)[0]  # Remove extension

        # Match everything before the final _UUID
        m2 = re.match(r'^(.*)_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', base_name)
        if m2:
            tool_pattern = m2.group(1).lower() + "_"
        else:
            tool_pattern = base_name.lower() + "_"

        meta["tool_filename_patterns"][tool_name] = tool_pattern

        if module not in meta["tool_categories"]:
            meta["tool_categories"][module] = []

        if tool_name not in meta["tool_categories"][module]:
            meta["tool_categories"][module].append(tool_name)

        # Save it back
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

            

        return jsonify({
            "status": "success",
            "message": f"Processed {tool_name} from {module}. Reports left: {reports_left}"
        })

    # Dashboard Stats
    @app.route("/vuln_stats", methods=["GET"])
    def vuln_stats():
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_groq import ChatGroq

        # Independent LLM for stats
        stat_prompt = ChatPromptTemplate.from_template("""
            Based on the following module report, extract both the count and short descriptions of vulnerabilities.

            Format your answer strictly as valid JSON like this:
            {{
                "counts": {{
                    "High": 2,
                    "Medium": 3,
                    "Low": 1,
                    "Info": 2
                }},
                "descriptions": {{
                    "High": ["SQL Injection in login form", "Privilege escalation via URL"],
                    "Medium": ["XSS in search field", "Sensitive data exposure", "Outdated server header"],
                    "Low": ["Clickjacking on contact page"],
                    "Info": ["Open ports detected", "Server version disclosed"]
                }}
            }}

            Report:
            {report}
        """)
        stat_chain = stat_prompt | ChatGroq(
            temperature=TEMPERATURE,
            groq_api_key=GROQ_API_KEY,
            model_name=GROQ_MODEL_NAME
        )

        auth_token = session.get("auth_token")
        modules = session.get("modules")

        if not auth_token or not modules:
            return jsonify({"error": "Unauthorized or incomplete session"}), 401

        category_stats = {}

        for module in modules:
            report_path = os.path.join(DIR, UPLOAD_FOLDER, f"module_report_{module}_{auth_token}.txt")
            if os.path.exists(report_path):
                with open(report_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    try:
                        combined_result = stat_chain.invoke({"report": content})

                        def extract_json(text):
                            match = re.search(r"\{.*\}", text, re.DOTALL)
                            return json.loads(match.group(0)) if match else {}

                        result_json = extract_json(combined_result.content)
                        category_stats[module] = {
                            "counts": result_json.get("counts", {}),
                            "descriptions": result_json.get("descriptions", {})
                        }
                    except Exception as e:
                        print(f"[vuln_stats] error: {e}")
                        continue

        return jsonify({"by_category": category_stats})

    @app.route("/get", methods=["GET", "POST"])
    def chatbot():
        msg = request.form["msg"]
        print("RR", session.get("report_ready", False))
        
        # Initialize session context if it doesn't exist
        if "context" not in session:
            session["context"] = generate_initial_context(context=session.get("tools"))
        
        # If report is ready, just get the response without additional processing
        if session.get("report_ready", False):
            print("[DEBUG] Report is going to QnA")
            # Pass the current session context to get_chat_qna
            result = get_chat_qna(msg, session["context"])
            # Parse JSON result
            result_data = json.loads(result)
            # Update session context from response
            session["context"] = result_data.get("context", session["context"])
            return result_data.get("response", "Error processing response")
        
        # Otherwise, continue with normal processing
        # Pass the current session context to get_chat_response
        result = get_chat_response(msg, session["context"])
        result_data = json.loads(result)
        
        # Update the session context if it was returned in the response
        if "context" in result_data:
            session["context"] = result_data.get("context")
        
        # If we got a successful extraction with URL and modules
        if result_data.get("status") == "success" and "url" in result_data and "modules" in result_data:
            try:
                token = str(uuid.uuid4())
                url = result_data["url"]
                modules = result_data["modules"]
                
                if not isinstance(modules, list):
                    modules = [modules]
                
                modules = [str(m) for m in modules]
                
                if len(modules) == 0:
                    return result_data.get("response", "No modules specified")
                
                try:
                    requests.post(session["remote_endpoint"], json={
                        "Auth": "Valid",
                        "URL": url,
                        "Token": token,
                        "MODULES": modules
                    })
                except Exception as e:
                    return jsonify({"error": f"Failed to send to remote: {str(e)}"}), 500
                
                session["auth_token"] = token
                session["url"] = url
                session["modules"] = modules
                session["report_ready"] = False
                return "Please Wait while we're Processing..."
                
            except Exception as e:
                print(f"Error processing response: {str(e)}")
                print(f"Response was: {result}")
                return f"Error parsing input: {str(e)}", 400
        
        # Return the fallback response if no URL/modules were extracted
        return result_data.get("response", "Error processing request")


    
    @app.route("/stat", methods=["GET"])
    def stat():
        """Return stats about file processing for a token"""
        auth_token = session.get("auth_token")
        if not auth_token:
            return jsonify({"error": "Unauthorized - No auth token provided"}), 401
        
        # Query the database for stats
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM file_stats WHERE token = ?', (auth_token,))
        record = cursor.fetchone()
        conn.close()
        
        if not record:
            return jsonify({
                "token": auth_token,
                "files_processed": 0,
                "total_files": 0,
                "status": "No files processed yet"
            })
        
        return jsonify({
            "token": auth_token,
            "files_processed": record["files_processed"],
            "total_files": record["total_files"],
            "status": "complete" if record["files_processed"] >= record["total_files"] else "in_progress",
            "percentage": (record["files_processed"] / record["total_files"] * 100) if record["total_files"] > 0 else 0
        })
    
    @app.route("/file/<filename>", methods=["GET"])
    def fetch_file(filename):
        """Return the requested file from the uploaded files directory"""
        auth_token = session.get("auth_token")
        if not auth_token:
            return jsonify({"error": "Unauthorized - No auth token provided"}), 401
        
        if not filename:
            return jsonify({"error": "No filename provided"}), 400
        
        # Convert auth_token to string to ensure we can use it in string comparison
        auth_token_str = str(auth_token)
        
        # Get all files in the upload directory
        upload_dir = os.path.join(DIR, UPLOAD_FOLDER)
        all_files = os.listdir(upload_dir)
        token_files = [f for f in all_files if auth_token_str in f]
        
        # Security check: ensure the requested file belongs to this token
        if auth_token_str not in filename and not filename.endswith(f"_{auth_token_str}.txt"):
            # If token is not in the filename, check if it's in the list of files for this token
            if filename not in token_files:
                return jsonify({"error": "Unauthorized access to file"}), 403
        
        # Get the full path to the file
        file_path = os.path.join(DIR, UPLOAD_FOLDER, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({"error": f"File {filename} not found"}), 404
        
        # Determine the appropriate MIME type based on file extension
        if filename.endswith('.json'):
            mimetype = "application/json"
        elif filename.endswith('.xml'):
            mimetype = "application/xml"
        else:
            mimetype = "text/plain"
        
        # Return the file
        return send_file(file_path, mimetype=mimetype)
