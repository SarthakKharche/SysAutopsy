import pandas as pd
from datetime import datetime
from firebase_config import db
from ai_config import generate_ai_root_cause_analysis, generate_incident_summary, categorize_incident

def to_minutes(t):
    dt = datetime.strptime(t, "%H:%M")
    return dt.hour * 60 + dt.minute

def extract_event_sequence(timeline):
    """Extract event names from timeline for pattern matching"""
    events = []
    for entry in timeline:
        # Extract event name from timeline entry
        # Format: "timestamp – EVENT_NAME (severity)"
        parts = entry.split("–")
        if len(parts) > 1:
            event_part = parts[1].strip()
            event_name = event_part.split("(")[0].strip()
            events.append(event_name)
    return events

def calculate_similarity(seq1, seq2):
    """Calculate similarity between two event sequences"""
    if not seq1 or not seq2:
        return 0
    matches = sum(1 for a, b in zip(seq1, seq2) if a == b)
    return matches / max(len(seq1), len(seq2))

def detect_risk_warning(current_sequence):
    """Check if current sequence matches past failure patterns"""
    try:
        docs = db.collection("failure_signatures").stream()
        
        for doc in docs:
            past_data = doc.to_dict()
            past_sequence = past_data.get("sequence", [])
            similarity = calculate_similarity(current_sequence, past_sequence)
            
            if similarity >= 0.6:
                return {
                    "risk": "HIGH",
                    "message": "Current behavior resembles a past failure pattern.",
                    "similarity": round(similarity * 100, 2),
                    "matched_cause": past_data.get("root_cause", "Unknown")
                }
        
        return None
    except Exception as e:
        print(f"Error detecting risk warning: {e}")
        return None

def analyze_logs(file_path):
    logs = pd.read_csv(file_path)
    logs_sorted = logs.sort_values("timestamp")

    timeline = [
        f"{row['timestamp']} – {row['event']} ({row['severity']})"
        for _, row in logs_sorted.iterrows()
    ]

    ignored_alert = any(logs_sorted["event"] == "ALERT_IGNORED")
    manual_override = any(logs_sorted["event"] == "MANUAL_OVERRIDE")

    times = logs_sorted["timestamp"].apply(to_minutes).tolist()
    delay_minutes = times[-1] - times[0]

    missed_intervention = None

    if ignored_alert and delay_minutes > 10:
        missed_intervention = {
             "point": "After critical alert was raised",
             "message": f"Failure could likely have been prevented if alert was acknowledged within 10 minutes. Actual delay was {delay_minutes} minutes."
        }

    

    scores = {
        "Ignored Alerts": 60 if ignored_alert else 0,
        "Manual Override": 25 if manual_override else 0,
        "Delayed Response": 15 if delay_minutes > 30 else 0
    }

    total = sum(scores.values())
    probabilities = {
        k: round((v / total) * 100, 2) if total > 0 else 0
        for k, v in scores.items()
    }

    explanations = {}
    if ignored_alert:
        explanations["Ignored Alerts"] = "Critical alert raised but not acknowledged."
    if manual_override:
        explanations["Manual Override"] = "Manual override increased system risk."
    if delay_minutes > 30:
        explanations["Delayed Response"] = f"{delay_minutes}-minute delay detected."

    # Automated Postmortem Summary
    primary_cause = max(probabilities, key=probabilities.get)
    preventability = "High" if primary_cause == "Ignored Alerts" else "Medium"
    
    recommendations = {
        "Ignored Alerts": "Introduce alert acknowledgment SLAs and escalation mechanisms.",
        "Manual Override": "Limit manual overrides and add approval workflows.",
        "Delayed Response": "Improve incident response time and monitoring visibility."
    }
    recommended_action = recommendations.get(primary_cause, "Review system safeguards.")
    
    postmortem_summary = {
        "primary_cause": primary_cause,
        "preventability": preventability,
        "recommended_action": recommended_action
    }

    # Extract event sequence for pattern matching
    event_sequence = extract_event_sequence(timeline)
    
    # Detect risk based on past patterns
    risk_warning = detect_risk_warning(event_sequence)
    
    # Store failure signature for future learning
    try:
        db.collection("failure_signatures").add({
            "sequence": event_sequence,
            "root_cause": primary_cause,
            "preventability": preventability,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        print(f"Error storing failure signature: {e}")

    # AI-Powered Root Cause Analysis
    ai_analysis = generate_ai_root_cause_analysis(
        timeline=timeline,
        probabilities=probabilities,
        explanations=explanations,
        missed_intervention=missed_intervention
    )
    
    # AI-Powered Incident Categorization
    incident_category = categorize_incident(
        timeline=timeline,
        probabilities=probabilities,
        explanations=explanations
    )
    
    # Generate executive summary
    executive_summary = generate_incident_summary(ai_analysis, postmortem_summary)

    return {
        "timeline": timeline,
        "probabilities": probabilities,
        "explanations": explanations,
        "missed_intervention": missed_intervention,
        "postmortem_summary": postmortem_summary,
        "risk_warning": risk_warning,
        "ai_analysis": ai_analysis,
        "incident_category": incident_category,
        "executive_summary": executive_summary
    }
