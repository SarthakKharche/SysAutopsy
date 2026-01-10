"""
GenAI Explanation Layer
Purpose: Use GenAI strictly for explanation, not decision-making
All analytical decisions remain rule-based and auditable
"""
import os
import google.generativeai as genai

# Configure Gemini for explanations only
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
genai_available = False

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        explanation_model = genai.GenerativeModel('gemini-2.5-flash')
        genai_available = True
    except Exception as e:
        print(f"GenAI explanation model failed to initialize: {e}")
        explanation_model = None
else:
    explanation_model = None


def generate_explanation(context):
    """
    Generate human-readable explanation from structured analytical results
    
    IMPORTANT: GenAI receives ONLY structured results, never raw logs
    Decisions are made by rules/AI context engine, GenAI only explains
    """
    
    # If GenAI is available, use it for natural language explanation
    if genai_available and explanation_model:
        return generate_genai_explanation(context)
    else:
        # Fallback to template-based explanation
        return generate_template_explanation(context)


def generate_genai_explanation(context):
    """Use Gemini to generate natural, conversational explanation"""
    
    try:
        prompt = f"""You are a system reliability engineer explaining an incident analysis to operations teams.

Generate a clear, professional incident summary based on these FACTS (already analyzed):

Incident: {context['incident_title']}
System: {context['system']}
Environment: {context['environment']}
Severity: {context['severity']}

PRIMARY ROOT CAUSE (determined by analysis engine):
{context['primary_root_cause']} ({context['root_cause_breakdown'].get(context['primary_root_cause'], 0)}% contribution)

OTHER CONTRIBUTING FACTORS:
{format_breakdown(context['root_cause_breakdown'], exclude=context['primary_root_cause'])}

MISSED INTERVENTION: {'Yes - Alerts not acted upon within ' + context.get('dynamic_threshold', 'threshold') if context.get('missed_intervention') else 'No'}

HISTORICAL CONTEXT:
Similar to {context.get('similar_incidents', 0)} past incident(s)

PREVENTION RECOMMENDATIONS (from analysis engine):
{format_prevention_rules(context.get('prevention_rules', []))}

Write a 3-paragraph explanation:
1. What happened and primary cause
2. Why it happened (contributing factors and missed interventions)
3. Prevention guidance (what to do differently)

Keep it professional, concise, and actionable. No bullet points."""

        response = explanation_model.generate_content(prompt)
        return response.text.strip()
    
    except Exception as e:
        print(f"GenAI explanation failed: {e}")
        return generate_template_explanation(context)


def generate_template_explanation(context):
    """Template-based explanation (fallback or for deterministic output)"""
    
    primary_cause = context['primary_root_cause']
    contribution = context['root_cause_breakdown'].get(primary_cause, 0)
    
    explanation = f"""Incident Summary:
The incident titled '{context['incident_title']}' occurred in the {context['environment']} environment with severity {context['severity']}. The system '{context['system']}' experienced a failure requiring investigation.

Root Cause Analysis:
The primary root cause identified was '{primary_cause}', contributing approximately {contribution}% to the failure. """
    
    # Add other contributing factors
    other_factors = [f"{k} ({v}%)" for k, v in context['root_cause_breakdown'].items() 
                    if k != primary_cause and v > 0]
    if other_factors:
        explanation += f"Other contributing factors include: {', '.join(other_factors)}. "
    
    # Missed intervention
    if context.get('missed_intervention'):
        explanation += f"\n\nMissed Intervention:\nA critical intervention opportunity was missed. Alerts were not acted upon within the dynamic threshold of {context.get('dynamic_threshold', 'the configured threshold')}, increasing system risk. "
    
    # Historical learning
    if context.get('similar_incidents', 0) > 0:
        explanation += f"\n\nLearning from History:\nThis incident closely resembles {context['similar_incidents']} past incident(s), which influenced the adaptive analysis and confidence adjustments. "
    else:
        explanation += f"\n\nLearning from History:\nThis is the first incident of this type. The analysis establishes a baseline for future pattern detection. "
    
    # Prevention guidance
    if context.get('prevention_rules'):
        explanation += "\n\nPrevention Guidance:\nTo prevent recurrence, SysAutopsy recommends:\n"
        for i, rule in enumerate(context['prevention_rules'], 1):
            explanation += f"- {rule}\n"
    
    return explanation.strip()


def format_breakdown(breakdown, exclude=None):
    """Format root cause breakdown for prompt"""
    items = []
    for cause, percentage in breakdown.items():
        if cause != exclude and percentage > 0:
            items.append(f"- {cause}: {percentage}%")
    return "\n".join(items) if items else "None"


def format_prevention_rules(rules):
    """Format prevention rules for prompt"""
    if not rules:
        return "Review system alerts and monitoring thresholds"
    return "\n".join([f"- {rule}" for rule in rules])


def build_explanation_context(report, metadata):
    """
    Build structured context for explanation generation
    This is what goes to GenAI - structured results, NOT raw logs
    """
    
    context = {
        "incident_title": metadata.get("incident_title", "Unnamed Incident"),
        "system": metadata.get("system_name", "Unknown System"),
        "environment": metadata.get("environment", "unknown"),
        "severity": metadata.get("severity", "unknown"),
        "primary_root_cause": report.get("primary_root_cause", "Unknown"),
        "root_cause_breakdown": report.get("probabilities", {}),
        "missed_intervention": report.get("missed_intervention") is not None,
        "dynamic_threshold": None,
        "similar_incidents": 0,
        "prevention_rules": []
    }
    
    # Extract adaptive analysis data if available
    if "adaptive_analysis" in report:
        adaptive = report["adaptive_analysis"]
        context["similar_incidents"] = adaptive.get("similar_incidents_found", 0)
        
        if "dynamic_thresholds_used" in adaptive:
            threshold = adaptive["dynamic_thresholds_used"].get("alert_ignore", "N/A")
            context["dynamic_threshold"] = f"{threshold} minutes"
    
    # Extract prevention rules from postmortem
    if "postmortem_summary" in report:
        pm = report["postmortem_summary"]
        if "recommended_action" in pm:
            context["prevention_rules"].append(pm["recommended_action"])
    
    # Add pattern-based prevention rules
    if report.get("prevention_rules"):
        context["prevention_rules"].extend(report["prevention_rules"][:2])
    
    return context
