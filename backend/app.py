from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
from datetime import datetime
from analysis import analyze_logs
from firebase_config import db
from ai_context import run_adaptive_analysis
from genai_explainer import generate_explanation, build_explanation_context
from chatbot_handler import answer_question, get_suggested_questions
from auth_handler import register_user, login_user, get_user_by_id
from project_handler import (
    create_project, get_user_projects, get_project, update_project,
    delete_project, add_log_to_project, get_project_logs,
    get_project_reports, get_project_context_for_analysis
)

print("Starting SysAutopsy backend...")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sysautopsy-secret-key-change-in-production')
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============ Authentication Decorator ============
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============ Auth Routes ============
@app.route("/login")
def login_page():
    if 'user_id' in session:
        return redirect('/projects')
    return render_template("login.html")


@app.route("/auth/register", methods=["POST"])
def auth_register():
    try:
        data = request.json
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        recaptcha_token = data.get("recaptcha_token", "")
        
        if not name or not email or not password:
            return jsonify({"error": "All fields are required"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        # Verify reCAPTCHA
        from auth_handler import verify_recaptcha
        if not verify_recaptcha(recaptcha_token):
            return jsonify({"error": "reCAPTCHA verification failed. Please try again."}), 400
        
        result = register_user(name, email, password)
        
        if result["success"]:
            session['user_id'] = result["user"]["id"]
            session['user_name'] = result["user"]["name"]
            session['user_email'] = result["user"]["email"]
            return jsonify(result["user"])
        else:
            return jsonify({"error": result["error"]}), 400
            
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({"error": "Registration failed"}), 500


@app.route("/auth/login", methods=["POST"])
def auth_login():
    try:
        data = request.json
        email = data.get("email", "").strip()
        password = data.get("password", "")
        recaptcha_token = data.get("recaptcha_token", "")
        
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400
        
        # Verify reCAPTCHA
        from auth_handler import verify_recaptcha
        if not verify_recaptcha(recaptcha_token):
            return jsonify({"error": "reCAPTCHA verification failed. Please try again."}), 400
        
        result = login_user(email, password)
        
        if result["success"]:
            session['user_id'] = result["user"]["id"]
            session['user_name'] = result["user"]["name"]
            session['user_email'] = result["user"]["email"]
            return jsonify(result["user"])
        else:
            return jsonify({"error": result["error"]}), 400
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/auth/google", methods=["POST"])
def auth_google():
    """Handle Google Sign-In"""
    try:
        data = request.json
        email = data.get("email", "").strip()
        name = data.get("name", "").strip()
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Import google auth function
        from auth_handler import google_auth_user
        
        result = google_auth_user(email, name)
        
        if result["success"]:
            session['user_id'] = result["user"]["id"]
            session['user_name'] = result["user"]["name"]
            session['user_email'] = result["user"]["email"]
            return jsonify(result["user"])
        else:
            return jsonify({"error": result["error"]}), 400
            
    except Exception as e:
        print(f"Google auth error: {e}")
        return jsonify({"error": "Google authentication failed"}), 500


@app.route("/auth/me")
def auth_me():
    if 'user_id' not in session:
        return jsonify({"error": "Not authenticated"}), 401
    
    return jsonify({
        "id": session.get('user_id'),
        "name": session.get('user_name'),
        "email": session.get('user_email')
    })


# ============ Project Routes ============
@app.route("/projects")
def projects_page():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template("projects.html")


@app.route("/projects/list")
@login_required
def projects_list():
    user_id = session['user_id']
    projects = get_user_projects(user_id)
    return jsonify(projects)


@app.route("/projects/create", methods=["POST"])
@login_required
def projects_create():
    try:
        data = request.json
        name = data.get("name", "").strip()
        description = data.get("description", "").strip()
        system_name = data.get("system_name", "").strip()
        
        if not name:
            return jsonify({"error": "Project name is required"}), 400
        
        result = create_project(session['user_id'], name, description, system_name)
        
        if result["success"]:
            return jsonify(result["project"])
        else:
            return jsonify({"error": result["error"]}), 400
            
    except Exception as e:
        print(f"Create project error: {e}")
        return jsonify({"error": "Failed to create project"}), 500


@app.route("/projects/select", methods=["POST"])
@login_required
def projects_select():
    try:
        data = request.json
        project_id = data.get("project_id")
        
        if not project_id:
            return jsonify({"error": "Project ID required"}), 400
        
        # Verify project belongs to user
        project = get_project(project_id, session['user_id'])
        if not project:
            return jsonify({"error": "Project not found"}), 404
        
        session['current_project_id'] = project_id
        session['current_project_name'] = project['name']
        
        return jsonify({"success": True, "project": project})
        
    except Exception as e:
        print(f"Select project error: {e}")
        return jsonify({"error": "Failed to select project"}), 500


@app.route("/projects/current")
@login_required
def projects_current():
    project_id = session.get('current_project_id')
    if not project_id:
        return jsonify({"error": "No project selected"}), 404
    
    project = get_project(project_id, session['user_id'])
    if not project:
        return jsonify({"error": "Project not found"}), 404
    
    return jsonify(project)


@app.route("/projects/<project_id>/logs")
@login_required
def project_logs_list(project_id):
    # Verify project belongs to user
    project = get_project(project_id, session['user_id'])
    if not project:
        return jsonify({"error": "Project not found"}), 404
    
    logs = get_project_logs(project_id)
    return jsonify(logs)


@app.route("/projects/<project_id>/reports")
@login_required
def project_reports_list(project_id):
    # Verify project belongs to user
    project = get_project(project_id, session['user_id'])
    if not project:
        return jsonify({"error": "Project not found"}), 404
    
    reports = get_project_reports(project_id)
    return jsonify(reports)


@app.route("/projects/view-report", methods=["POST"])
@login_required
def view_report():
    """Store a report ID in session to view in dashboard"""
    try:
        data = request.json
        report_id = data.get("report_id")
        print(f"view_report: Setting report_id = {report_id}")
        
        if not report_id:
            return jsonify({"error": "Report ID required"}), 400
        
        session['view_report_id'] = report_id
        session.modified = True  # Ensure session is saved
        print(f"view_report: Session view_report_id set to {session.get('view_report_id')}")
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"View report error: {e}")
        return jsonify({"error": "Failed to set report"}), 500


@app.route("/api/get-saved-report")
@login_required
def get_saved_report():
    """Get a saved report from session"""
    report_id = session.get('view_report_id')
    print(f"get_saved_report: report_id from session = {report_id}")
    
    if not report_id:
        return jsonify({"error": "No report selected"}), 404
    
    # Clear it after fetching
    session.pop('view_report_id', None)
    
    # Get the report from Firebase
    try:
        project_id = session.get('current_project_id')
        print(f"get_saved_report: project_id = {project_id}")
        if project_id:
            reports = get_project_reports(project_id)
            print(f"get_saved_report: Found {len(reports)} reports")
            for report in reports:
                print(f"get_saved_report: Checking report id {report.get('id')} vs {report_id}")
                if report.get('id') == report_id:
                    analysis_data = report.get('analysis', report)
                    print(f"get_saved_report: Found matching report, returning analysis")
                    return jsonify(analysis_data)
        
        return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        print(f"Get saved report error: {e}")
        return jsonify({"error": "Failed to get report"}), 500


@app.route("/api/report/<report_id>")
@login_required
def get_report_by_id(report_id):
    """Get a specific report by ID from Firebase"""
    try:
        project_id = session.get('current_project_id')
        if not project_id:
            return jsonify({"error": "No project selected"}), 400
        
        reports = get_project_reports(project_id)
        for report in reports:
            if report.get('id') == report_id:
                # Return the analysis data from the report
                analysis_data = report.get('analysis', report)
                return jsonify(analysis_data)
        
        return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        print(f"Get report by ID error: {e}")
        return jsonify({"error": "Failed to get report"}), 500


# ============ Dashboard Route ============
@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    if 'current_project_id' not in session:
        return redirect('/projects')
    return render_template("index.html")


@app.route("/")
def index():
    # Redirect to login if not authenticated
    if 'user_id' not in session:
        return redirect('/login')
    # Always redirect to projects page when opening the site
    return redirect('/projects')


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        
        # Get current project
        project_id = session.get('current_project_id')
        if not project_id:
            return jsonify({"error": "No project selected. Please select a project first."}), 400
        
        # Create project-specific upload folder
        project_upload_folder = os.path.join(UPLOAD_FOLDER, project_id)
        os.makedirs(project_upload_folder, exist_ok=True)
        filepath = os.path.join(project_upload_folder, file.filename)
        file.save(filepath)

        # Collect incident metadata from form
        metadata = {
            "incident_title": request.form.get("incident_title", ""),
            "system_name": request.form.get("system_name", ""),
            "environment": request.form.get("environment", ""),
            "severity": request.form.get("severity", ""),
            "incident_type": request.form.get("incident_type", ""),
            "owning_team": request.form.get("owning_team", ""),
            "alert_triggered": request.form.get("alert_triggered", "No"),
            "manual_intervention": request.form.get("manual_intervention", "No"),
            "timestamp": datetime.now().isoformat(),
            "filename": file.filename,
            "project_id": project_id
        }

        # Run base analysis
        base_report = analyze_logs(filepath)
        
        # 🧠 Get historical context from previous logs in this project
        project_context = get_project_context_for_analysis(project_id)
        
        # 🧠 AI CONTEXT ENGINE - Adaptive Analysis v1
        # Wraps AI intelligence around base analysis
        adaptive_analysis = run_adaptive_analysis(
            base_report, 
            metadata, 
            base_report.get("timeline", []),
            project_context  # Pass historical context
        )
        
        # Merge base report with adaptive analysis
        report = base_report.copy()
        report["metadata"] = metadata
        report["adaptive_analysis"] = adaptive_analysis
        report["project_id"] = project_id
        report["project_name"] = session.get('current_project_name', '')
        
        # Add historical context info to report
        if project_context:
            report["historical_context"] = {
                "previous_analyses": project_context["previous_analyses_count"],
                "recurring_issues": project_context["most_common_issues"],
                "context_used": True
            }
        else:
            report["historical_context"] = {
                "previous_analyses": 0,
                "recurring_issues": [],
                "context_used": False
            }
        
        # Override probabilities with AI-adjusted ones
        report["probabilities"] = adaptive_analysis["adjusted_probabilities"]
        report["primary_root_cause"] = adaptive_analysis["primary_root_cause"]
        report["risk_level"] = adaptive_analysis["risk_level"]
        report["ai_enhanced"] = True
        
        # GenAI EXPLANATION LAYER - Use GenAI for explanation, not decision
        # All decisions made above, GenAI only translates to human language
        explanation_context = build_explanation_context(report, metadata)
        report["ai_explanation"] = generate_explanation(explanation_context)
        
        # AI Confidence (for visualization)
        report["ai_confidence"] = min(adaptive_analysis["similar_incidents_found"] * 20, 100)
        
        # Store minimal analysis info in session for chatbot context (avoid large cookie)
        session['current_analysis_summary'] = {
            'primary_root_cause': report.get('primary_root_cause', ''),
            'risk_level': report.get('risk_level', ''),
            'metadata': metadata
        }
        
        # Generate suggested questions for chatbot
        report["suggested_questions"] = get_suggested_questions(report)

        # Store log and report in project (handles sanitization internally)
        add_log_to_project(project_id, metadata, report)

        return jsonify(report)

    except Exception as e:
        print("ERROR during analysis:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/chat", methods=["POST"])
def chat():
    """AI Chatbot endpoint - answers questions about current analysis"""
    try:
        data = request.json
        question = data.get("question", "")
        
        if not question:
            return jsonify({"error": "No question provided"}), 400
        
        # Get current analysis from session
        analysis_context = session.get('current_analysis', {})
        
        if not analysis_context:
            return jsonify({
                "answer": "Please analyze a log file first before asking questions."
            })
        
        # Get AI answer
        answer = answer_question(question, analysis_context)
        
        return jsonify({
            "question": question,
            "answer": answer
        })
    
    except Exception as e:
        print("ERROR in chat:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/firebase-test")
def firebase_test():
    db.collection("test").add({
        "status": "firebase is working",
        "source": "sysautopsy"
    })
    return "Firebase write successful"

@app.route("/past-reports")
@login_required
def past_reports():
    """Get past reports - filtered by current project if one is selected"""
    project_id = session.get('current_project_id')
    
    if project_id:
        # Get project-specific reports
        reports = get_project_reports(project_id)
        # Extract just the analysis data from each report
        result = []
        for report in reports:
            analysis = report.get("analysis", {})
            analysis["id"] = report.get("id")
            analysis["created_at"] = report.get("created_at")
            result.append(analysis)
        return jsonify(result)
    else:
        # Fallback to all reports (for backward compatibility)
        docs = db.collection("reports").stream()
        reports = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            reports.append(data)
        return jsonify(reports)


@app.route("/scheduled-analysis")
def scheduled_analysis():
    """Generate prevention rules from recurring failure patterns"""
    try:
        docs = db.collection("failure_signatures").stream()
        pattern_count = {}
        
        # Count pattern occurrences
        for doc in docs:
            data = doc.to_dict()
            seq = tuple(data.get("sequence", []))
            if seq:
                if seq not in pattern_count:
                    pattern_count[seq] = {
                        "count": 0,
                        "root_cause": data.get("root_cause", "Unknown")
                    }
                pattern_count[seq]["count"] += 1
        
        # Generate rules for recurring patterns
        rules = []
        for pattern, info in pattern_count.items():
            if info["count"] >= 3:  # threshold
                rule = {
                    "pattern": " → ".join(pattern),
                    "risk_level": "HIGH",
                    "derived_from_incidents": info["count"],
                    "root_cause": info["root_cause"],
                    "rule_text": "Escalate alerts and restrict manual overrides for this sequence.",
                    "timestamp": datetime.now().isoformat()
                }
                rules.append(rule)
                
                # Store in prevention_rules collection
                db.collection("prevention_rules").add(rule)
        
        return jsonify({
            "status": "success",
            "rules_generated": len(rules),
            "rules": rules
        })
    
    except Exception as e:
        print(f"Error in scheduled analysis: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/prevention-rules")
def get_prevention_rules():
    """Get all generated prevention rules"""
    try:
        docs = db.collection("prevention_rules").stream()
        rules = []
        
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            rules.append(data)
        
        return jsonify(rules)
    
    except Exception as e:
        print(f"Error fetching prevention rules: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("Running Flask server...")
    app.run(debug=True, use_reloader=False)
