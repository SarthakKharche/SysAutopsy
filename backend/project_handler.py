"""
Project Handler - Manage projects and associated logs
"""
from datetime import datetime
import json
from firebase_config import db


def sanitize_for_firestore(obj, max_depth=10, current_depth=0):
    """
    Sanitize an object for Firestore storage.
    Converts deeply nested objects and problematic types to JSON strings.
    """
    if current_depth > max_depth:
        return str(obj)
    
    if obj is None:
        return None
    elif isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            sanitized = sanitize_for_firestore(value, max_depth, current_depth + 1)
            result[key] = sanitized
        return result
    elif isinstance(obj, list):
        return [sanitize_for_firestore(item, max_depth, current_depth + 1) for item in obj]
    else:
        # Convert other types to string
        return str(obj)


def create_project(user_id, name, description="", system_name=""):
    """Create a new project for a user"""
    try:
        project_data = {
            "user_id": user_id,
            "name": name,
            "description": description,
            "system_name": system_name,
            "log_count": 0,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        doc_ref = db.collection("projects").add(project_data)
        project_id = doc_ref[1].id
        
        return {
            "success": True,
            "project": {
                "id": project_id,
                **project_data
            }
        }
        
    except Exception as e:
        print(f"Create project error: {e}")
        return {"success": False, "error": "Failed to create project"}


def get_user_projects(user_id):
    """Get all projects for a user"""
    try:
        projects_ref = db.collection("projects")
        docs = projects_ref.where("user_id", "==", user_id).stream()
        
        projects = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            projects.append(data)
        
        # Sort by created_at descending
        projects.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return projects
        
    except Exception as e:
        print(f"Get projects error: {e}")
        return []


def get_project(project_id, user_id=None):
    """Get a specific project"""
    try:
        doc = db.collection("projects").document(project_id).get()
        if doc.exists:
            data = doc.to_dict()
            # Verify ownership if user_id provided
            if user_id and data.get("user_id") != user_id:
                return None
            data["id"] = doc.id
            return data
        return None
    except Exception as e:
        print(f"Get project error: {e}")
        return None


def update_project(project_id, user_id, updates):
    """Update a project"""
    try:
        # Verify ownership
        project = get_project(project_id, user_id)
        if not project:
            return {"success": False, "error": "Project not found"}
        
        updates["updated_at"] = datetime.now().isoformat()
        db.collection("projects").document(project_id).update(updates)
        
        return {"success": True}
        
    except Exception as e:
        print(f"Update project error: {e}")
        return {"success": False, "error": "Failed to update project"}


def delete_project(project_id, user_id):
    """Delete a project and its logs"""
    try:
        # Verify ownership
        project = get_project(project_id, user_id)
        if not project:
            return {"success": False, "error": "Project not found"}
        
        # Delete associated logs
        logs_ref = db.collection("project_logs")
        logs = logs_ref.where("project_id", "==", project_id).stream()
        for log in logs:
            log.reference.delete()
        
        # Delete project reports
        reports_ref = db.collection("project_reports")
        reports = reports_ref.where("project_id", "==", project_id).stream()
        for report in reports:
            report.reference.delete()
        
        # Delete project
        db.collection("projects").document(project_id).delete()
        
        return {"success": True}
        
    except Exception as e:
        print(f"Delete project error: {e}")
        return {"success": False, "error": "Failed to delete project"}


def add_log_to_project(project_id, log_data, analysis_result):
    """Add a log entry and its analysis to a project"""
    try:
        # Sanitize the analysis result for Firestore
        sanitized_analysis = sanitize_for_firestore(analysis_result)
        sanitized_log_data = sanitize_for_firestore(log_data)
        
        # Store log metadata
        log_entry = {
            "project_id": project_id,
            "filename": log_data.get("filename", ""),
            "uploaded_at": datetime.now().isoformat(),
            "metadata": sanitized_log_data,
            "summary": {
                "total_events": analysis_result.get("total_events", 0),
                "critical_events": analysis_result.get("critical_events", 0),
                "primary_root_cause": analysis_result.get("primary_root_cause", ""),
                "risk_level": analysis_result.get("risk_level", "")
            }
        }
        
        log_ref = db.collection("project_logs").add(log_entry)
        log_id = log_ref[1].id
        
        # Store full analysis report (sanitized for Firestore)
        report_entry = {
            "project_id": project_id,
            "log_id": log_id,
            "created_at": datetime.now().isoformat(),
            "analysis": sanitized_analysis
        }
        
        db.collection("project_reports").add(report_entry)
        
        # Update project log count
        project_ref = db.collection("projects").document(project_id)
        project = project_ref.get().to_dict()
        project_ref.update({
            "log_count": project.get("log_count", 0) + 1,
            "updated_at": datetime.now().isoformat()
        })
        
        return {"success": True, "log_id": log_id}
        
    except Exception as e:
        print(f"Add log error: {e}")
        return {"success": False, "error": "Failed to save log"}


def get_project_logs(project_id):
    """Get all logs for a project"""
    try:
        logs_ref = db.collection("project_logs")
        docs = logs_ref.where("project_id", "==", project_id).stream()
        
        logs = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            logs.append(data)
        
        # Sort by uploaded_at descending
        logs.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
        
        return logs
        
    except Exception as e:
        print(f"Get project logs error: {e}")
        return []


def get_project_reports(project_id):
    """Get all analysis reports for a project"""
    try:
        reports_ref = db.collection("project_reports")
        docs = reports_ref.where("project_id", "==", project_id).stream()
        
        reports = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            reports.append(data)
        
        # Sort by created_at descending
        reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return reports
        
    except Exception as e:
        print(f"Get project reports error: {e}")
        return []


def get_project_context_for_analysis(project_id):
    """
    Get historical context from previous logs in the project.
    This is used to provide the AI with context from previous analyses.
    """
    try:
        reports = get_project_reports(project_id)
        
        if not reports:
            return None
        
        # Build context from previous analyses
        context = {
            "previous_analyses_count": len(reports),
            "historical_root_causes": [],
            "historical_patterns": [],
            "recurring_issues": {},
            "timeline_of_incidents": []
        }
        
        for report in reports[:10]:  # Last 10 reports for context
            analysis = report.get("analysis", {})
            
            # Collect root causes
            root_cause = analysis.get("primary_root_cause")
            if root_cause:
                context["historical_root_causes"].append(root_cause)
                # Track recurring issues
                if root_cause in context["recurring_issues"]:
                    context["recurring_issues"][root_cause] += 1
                else:
                    context["recurring_issues"][root_cause] = 1
            
            # Collect patterns
            patterns = analysis.get("adaptive_analysis", {}).get("patterns_detected", [])
            context["historical_patterns"].extend(patterns)
            
            # Timeline entry
            context["timeline_of_incidents"].append({
                "date": report.get("created_at", ""),
                "root_cause": root_cause,
                "risk_level": analysis.get("risk_level", ""),
                "critical_events": analysis.get("critical_events", 0)
            })
        
        # Summarize recurring issues
        context["most_common_issues"] = sorted(
            context["recurring_issues"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return context
        
    except Exception as e:
        print(f"Get project context error: {e}")
        return None
