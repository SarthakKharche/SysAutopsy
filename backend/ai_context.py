"""
AI Context Engine - Adaptive Analysis v1
Implements context-aware intelligence without ML libraries
"""
from datetime import datetime
from firebase_config import db
from collections import Counter


# ==================== STEP 1: INCIDENT VECTOR REPRESENTATION ====================

def build_incident_vector(metadata, event_sequence):
    """Convert incident into structured feature vector for AI processing"""
    return {
        "system": metadata.get("system_name", "unknown"),
        "environment": metadata.get("environment", "unknown"),
        "severity": metadata.get("severity", "unknown"),
        "incident_type": metadata.get("incident_type", "unknown"),
        "alert_triggered": metadata.get("alert_triggered", "No"),
        "manual_intervention": metadata.get("manual_intervention", "No"),
        "sequence": event_sequence[:10]  # First 10 events as signature
    }


# ==================== STEP 2: SIMILARITY SCORING (AI LAYER 1) ====================

def similarity_score(current, past):
    """
    Calculate similarity between two incidents using feature matching
    Returns: 0.0 to 1.0 (AI similarity, not exact match)
    """
    score = 0
    total = 6

    # System match (most important)
    if current["system"] == past["system"]:
        score += 1
    
    # Environment match (critical for context)
    if current["environment"] == past["environment"]:
        score += 1
    
    # Severity match
    if current["severity"] == past["severity"]:
        score += 1
    
    # Incident type match
    if current["incident_type"] == past["incident_type"]:
        score += 1
    
    # Alert behavior match
    if current["alert_triggered"] == past["alert_triggered"]:
        score += 1
    
    # Manual intervention pattern match
    if current["manual_intervention"] == past["manual_intervention"]:
        score += 1

    return score / total


# ==================== STEP 3: CONTEXT-AWARE RE-WEIGHTING (AI LAYER 2) ====================

def adjust_root_causes(root_causes, metadata):
    """
    Dynamically adjust root cause probabilities based on incident context
    Same logs → different analysis depending on context
    """
    adjusted = root_causes.copy()

    # Production environment amplifies alert-related causes
    if metadata.get("environment") == "prod":
        if "Ignored Alerts" in adjusted:
            adjusted["Ignored Alerts"] += 10
        if "Alert System Failure" in adjusted:
            adjusted["Alert System Failure"] += 8

    # Manual intervention increases override risk weight
    if metadata.get("manual_intervention") == "Yes":
        if "Manual Override Risk" in adjusted:
            adjusted["Manual Override Risk"] += 15
        if "Human Error" in adjusted:
            adjusted["Human Error"] += 10

    # P1 severity amplifies urgency-related causes
    if metadata.get("severity") == "P1":
        if "Ignored Alerts" in adjusted:
            adjusted["Ignored Alerts"] += 10
        if "Configuration Error" in adjusted:
            adjusted["Configuration Error"] += 5

    # P2 severity moderate adjustment
    if metadata.get("severity") == "P2":
        if "Ignored Alerts" in adjusted:
            adjusted["Ignored Alerts"] += 5

    # Outage type increases system failure weights
    if metadata.get("incident_type") == "Outage":
        if "System Resource Exhaustion" in adjusted:
            adjusted["System Resource Exhaustion"] += 8
        if "Network Issues" in adjusted:
            adjusted["Network Issues"] += 5

    # No alert triggered suggests monitoring gaps
    if metadata.get("alert_triggered") == "No":
        if "Monitoring Gap" in adjusted:
            adjusted["Monitoring Gap"] += 12
        if "Alert System Failure" in adjusted:
            adjusted["Alert System Failure"] += 10

    # Normalize to 100%
    total = sum(adjusted.values())
    if total > 0:
        for k in adjusted:
            adjusted[k] = round((adjusted[k] / total) * 100, 2)

    return adjusted


# ==================== STEP 4: DYNAMIC RISK THRESHOLDS (AI LAYER 3) ====================

def get_alert_ignore_threshold(metadata):
    """
    Context-aware threshold for alert ignore detection
    Adapts sensitivity based on incident characteristics
    """
    severity = metadata.get("severity", "P4")
    environment = metadata.get("environment", "staging")
    
    # P1 in production = extremely sensitive
    if severity == "P1" and environment == "prod":
        return 3  # 3 minutes
    
    # P2 in production = very sensitive
    if severity == "P2" and environment == "prod":
        return 5  # 5 minutes
    
    # P1/P2 in staging = moderate
    if severity in ["P1", "P2"] and environment == "staging":
        return 8  # 8 minutes
    
    # P3 anywhere
    if severity == "P3":
        return 10  # 10 minutes
    
    # Default (P4 or unknown)
    return 15  # 15 minutes


def get_retry_threshold(metadata):
    """Dynamic threshold for retry attempt detection"""
    severity = metadata.get("severity", "P4")
    
    if severity == "P1":
        return 3  # 3 retries before alert
    elif severity == "P2":
        return 5
    else:
        return 10


def get_timeout_threshold(metadata):
    """Dynamic threshold for timeout detection (seconds)"""
    environment = metadata.get("environment", "staging")
    severity = metadata.get("severity", "P4")
    
    if environment == "prod" and severity in ["P1", "P2"]:
        return 30  # 30 seconds
    elif environment == "prod":
        return 60  # 1 minute
    else:
        return 120  # 2 minutes


# ==================== STEP 5: LEARN FROM PAST INCIDENTS (AI MEMORY) ====================

def store_incident_vector(incident_vector, final_root_cause, metadata):
    """
    Store incident vector in Firebase for future learning
    This builds the AI's experience database
    """
    try:
        db.collection("incident_vectors").add({
            "vector": incident_vector,
            "final_root_cause": final_root_cause,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat()
        })
        return True
    except Exception as e:
        print(f"Failed to store incident vector: {e}")
        return False


def find_similar_incidents(current_vector, threshold=0.7):
    """
    Find historically similar incidents using AI similarity scoring
    Returns: List of (past_incident, similarity_score) tuples
    """
    try:
        docs = db.collection("incident_vectors").stream()
        similar = []

        for doc in docs:
            data = doc.to_dict()
            past_vector = data.get("vector", {})
            score = similarity_score(current_vector, past_vector)
            
            if score >= threshold:
                similar.append({
                    "vector": past_vector,
                    "root_cause": data.get("final_root_cause", "Unknown"),
                    "similarity": round(score * 100, 2),
                    "timestamp": data.get("timestamp")
                })

        # Sort by similarity (highest first)
        similar.sort(key=lambda x: x["similarity"], reverse=True)
        return similar
    
    except Exception as e:
        print(f"Failed to find similar incidents: {e}")
        return []


# ==================== STEP 6: USE SIMILARITY TO ADJUST ANALYSIS ====================

def apply_historical_learning(root_causes, similar_incidents):
    """
    Adjust root cause analysis based on similar historical incidents
    This is adaptive intelligence - learning from experience
    """
    if not similar_incidents:
        return root_causes, None
    
    adjusted = root_causes.copy()
    
    # Extract root causes from similar incidents
    historical_causes = [inc["root_cause"] for inc in similar_incidents]
    
    # Find most common cause in similar incidents
    if historical_causes:
        cause_counter = Counter(historical_causes)
        dominant_cause, occurrences = cause_counter.most_common(1)[0]
        
        # Boost the dominant historical cause
        if dominant_cause in adjusted:
            boost = min(occurrences * 5, 20)  # Max 20% boost
            adjusted[dominant_cause] += boost
        
        # Normalize to 100%
        total = sum(adjusted.values())
        if total > 0:
            for k in adjusted:
                adjusted[k] = round((adjusted[k] / total) * 100, 2)
        
        learning_insight = {
            "dominant_cause": dominant_cause,
            "occurrences": occurrences,
            "boost_applied": boost
        }
        
        return adjusted, learning_insight
    
    return root_causes, None


def apply_project_context(root_causes, project_context):
    """
    Apply adjustments based on project-specific historical patterns
    Boosts probabilities for issues that recur within the same project
    """
    if not project_context:
        return root_causes
    
    adjusted = root_causes.copy()
    
    # Get recurring issues from project history
    recurring_issues = project_context.get("recurring_issues", {})
    most_common = project_context.get("most_common_issues", [])
    
    # Boost root causes that match recurring project issues
    for issue, count in most_common[:3]:  # Top 3 recurring issues
        if issue in adjusted:
            # More occurrences = higher boost (max 15%)
            boost = min(count * 5, 15)
            adjusted[issue] += boost
    
    # Normalize to 100%
    total = sum(adjusted.values())
    if total > 0:
        for k in adjusted:
            adjusted[k] = round((adjusted[k] / total) * 100, 2)
    
    return adjusted


def adjust_risk_for_project_patterns(risk_score, risk_level, project_context, root_causes):
    """
    Increase risk score if current issue matches a recurring project pattern
    """
    if not project_context:
        return risk_score, risk_level
    
    primary_cause = max(root_causes, key=root_causes.get) if root_causes else None
    recurring = project_context.get("recurring_issues", {})
    
    # If primary cause is a recurring issue, boost risk
    if primary_cause and primary_cause in recurring:
        occurrence_count = recurring[primary_cause]
        risk_boost = min(occurrence_count * 5, 20)  # Max 20 point boost
        risk_score = min(risk_score + risk_boost, 100)
        
        # Recalculate risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    
    return risk_score, risk_level


def calculate_adaptive_risk_level(metadata, similar_incidents, root_causes):
    """
    Calculate dynamic risk level based on context and history
    """
    risk_score = 0
    
    # Severity factor
    severity_scores = {"P1": 40, "P2": 30, "P3": 20, "P4": 10}
    risk_score += severity_scores.get(metadata.get("severity", "P4"), 10)
    
    # Environment factor
    if metadata.get("environment") == "prod":
        risk_score += 25
    else:
        risk_score += 10
    
    # Historical pattern factor
    if len(similar_incidents) >= 3:
        risk_score += 20  # Recurring pattern detected
    elif len(similar_incidents) >= 1:
        risk_score += 10
    
    # Manual intervention factor
    if metadata.get("manual_intervention") == "Yes":
        risk_score += 15
    
    # Alert failure factor
    if metadata.get("alert_triggered") == "No":
        risk_score += 15
    
    # Root cause certainty factor
    if root_causes:
        max_probability = max(root_causes.values())
        if max_probability >= 50:
            risk_score -= 10  # High certainty reduces overall risk
    
    # Determine risk level
    if risk_score >= 80:
        return "CRITICAL", risk_score
    elif risk_score >= 60:
        return "HIGH", risk_score
    elif risk_score >= 40:
        return "MEDIUM", risk_score
    else:
        return "LOW", risk_score


# ==================== STEP 7: MAIN ADAPTIVE ANALYSIS ORCHESTRATOR ====================

def run_adaptive_analysis(base_analysis, metadata, timeline, project_context=None):
    """
    Main AI Context Engine - wraps around base analysis
    
    Flow:
    1. Build incident vector
    2. Find similar historical incidents
    3. Adjust root causes with context
    4. Apply historical learning (including project history)
    5. Calculate adaptive risk
    6. Return enhanced analysis
    """
    
    # Build incident vector
    incident_vector = build_incident_vector(metadata, timeline)
    
    # Find similar incidents (AI memory)
    similar_incidents = find_similar_incidents(incident_vector, threshold=0.6)
    
    # Get base root causes
    base_root_causes = base_analysis.get("probabilities", {})
    
    # LAYER 1: Context-aware adjustment
    context_adjusted = adjust_root_causes(base_root_causes, metadata)
    
    # LAYER 1.5: Apply project historical context if available
    if project_context and project_context.get("most_common_issues"):
        context_adjusted = apply_project_context(context_adjusted, project_context)
    
    # LAYER 2: Historical learning adjustment
    final_adjusted, learning_insight = apply_historical_learning(
        context_adjusted, 
        similar_incidents
    )
    
    # LAYER 3: Calculate adaptive risk
    risk_level, risk_score = calculate_adaptive_risk_level(
        metadata, 
        similar_incidents, 
        final_adjusted
    )
    
    # Boost risk if recurring issue in project
    if project_context and project_context.get("recurring_issues"):
        risk_score, risk_level = adjust_risk_for_project_patterns(
            risk_score, risk_level, project_context, final_adjusted
        )
    
    # Get dynamic thresholds used
    thresholds_used = {
        "alert_ignore": get_alert_ignore_threshold(metadata),
        "retry_attempts": get_retry_threshold(metadata),
        "timeout_seconds": get_timeout_threshold(metadata)
    }
    
    # Find primary root cause
    primary_cause = max(final_adjusted, key=final_adjusted.get) if final_adjusted else "Unknown"
    
    # Store this incident for future learning
    store_incident_vector(incident_vector, primary_cause, metadata)
    
    # Build patterns detected list
    patterns_detected = []
    if learning_insight:
        patterns_detected.append(f"Historical pattern: {learning_insight['dominant_cause']}")
    if project_context and project_context.get("most_common_issues"):
        for issue, count in project_context["most_common_issues"][:3]:
            patterns_detected.append(f"Project recurring issue: {issue} ({count}x)")
    
    # Build adaptive response
    adaptive_response = {
        "ai_adjusted": True,
        "similar_incidents_found": len(similar_incidents),
        "similar_incidents": similar_incidents[:3],  # Top 3
        "risk_level": risk_level,
        "risk_score": risk_score,
        "dynamic_thresholds_used": thresholds_used,
        "context_adjustments_applied": True,
        "historical_learning_applied": learning_insight is not None,
        "project_context_applied": project_context is not None,
        "learning_insight": learning_insight,
        "primary_root_cause": primary_cause,
        "adjusted_probabilities": final_adjusted,
        "patterns_detected": patterns_detected,
        "explanation": generate_adaptive_explanation(
            metadata,
            len(similar_incidents), 
            risk_level,
            risk_score,
            learning_insight,
            thresholds_used,
            primary_cause
        )
    }
    
    return adaptive_response


def generate_adaptive_explanation(metadata, similar_count, risk_level, risk_score, learning_insight, thresholds, primary_cause):
    """Generate meaningful, actionable explanation of adaptive analysis as bullet points"""
    
    points = []
    
    # Risk assessment
    points.append(f"Risk: {risk_level} ({risk_score}/100)")
    
    # Environment context
    if metadata.get("environment") == "prod":
        points.append("Production environment increases urgency")
    else:
        points.append("Staging environment allows more investigation time")
    
    # Severity guidance
    severity = metadata.get("severity", "P4")
    severity_messages = {
        "P1": "Critical severity - immediate action required",
        "P2": "High severity - prioritize resolution",
        "P3": "Medium severity - schedule investigation",
        "P4": "Low severity - monitor for patterns"
    }
    points.append(severity_messages.get(severity, "Standard priority"))
    
    # Alert insights
    if metadata.get("alert_triggered") == "No":
        points.append("No alert fired - monitoring gap detected")
    else:
        points.append(f"Alert threshold set to {thresholds['alert_ignore']} min")
    
    # Manual intervention
    if metadata.get("manual_intervention") == "Yes":
        points.append("Human override detected - automation gap risk")
    
    # Historical learning
    if similar_count > 0:
        if learning_insight:
            points.append(f"Pattern match: '{learning_insight['dominant_cause']}' seen {learning_insight['occurrences']}x in similar cases ({similar_count} incidents analyzed)")
        else:
            points.append(f"Compared against {similar_count} similar incident(s) in history")
    else:
        points.append("First incident of this type - building baseline for future analysis")
    
    # Primary cause
    if primary_cause != "Unknown":
        points.append(f"Primary cause identified: {primary_cause}")
    
    return points
