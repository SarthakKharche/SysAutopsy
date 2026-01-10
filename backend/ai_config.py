import google.generativeai as genai
import os

# Configure Gemini API (Free tier)
# Get your free API key from: https://makersuite.google.com/app/apikey
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.5-flash')
else:
    model = None
    print("⚠️  GEMINI_API_KEY not found. AI features will be disabled.")
    print("   Get your free API key from: https://makersuite.google.com/app/apikey")
    print("   Then set it: $env:GEMINI_API_KEY='your-api-key-here' (PowerShell)")


def generate_ai_root_cause_analysis(timeline, probabilities, explanations, missed_intervention):
    """Use Gemini AI to generate intelligent root cause analysis"""
    
    if not model:
        return {
            "ai_enabled": False,
            "message": "AI analysis disabled. Set GEMINI_API_KEY to enable."
        }
    
    try:
        # Prepare context for AI
        context = f"""
You are an expert system reliability engineer analyzing a system failure.

## Failure Timeline:
{chr(10).join(timeline)}

## Root Cause Probabilities:
{chr(10).join([f"- {k}: {v}% ({explanations.get(k, '')})" for k, v in probabilities.items()])}

## Missed Intervention:
{missed_intervention if missed_intervention else "None detected"}

Based on this forensic data, provide:
1. A clear, concise root cause explanation (2-3 sentences)
2. Three specific, actionable prevention recommendations
3. Risk assessment: What could happen if this pattern repeats?

Format your response as:
ROOT CAUSE:
[your analysis]

PREVENTION STEPS:
1. [step 1]
2. [step 2]
3. [step 3]

RISK IF UNADDRESSED:
[risk assessment]
"""
        
        response = model.generate_content(context)
        
        # Parse AI response
        ai_text = response.text
        
        sections = {
            "root_cause": "",
            "prevention_steps": [],
            "risk_assessment": ""
        }
        
        current_section = None
        lines = ai_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if "ROOT CAUSE:" in line.upper():
                current_section = "root_cause"
            elif "PREVENTION" in line.upper():
                current_section = "prevention"
            elif "RISK" in line.upper():
                current_section = "risk"
            elif line:
                if current_section == "root_cause":
                    sections["root_cause"] += line + " "
                elif current_section == "prevention":
                    if line[0].isdigit() or line.startswith("-"):
                        sections["prevention_steps"].append(line.lstrip("0123456789.-) "))
                elif current_section == "risk":
                    sections["risk_assessment"] += line + " "
        
        return {
            "ai_enabled": True,
            "root_cause_explanation": sections["root_cause"].strip(),
            "prevention_recommendations": sections["prevention_steps"],
            "risk_assessment": sections["risk_assessment"].strip(),
            "raw_response": ai_text
        }
    
    except Exception as e:
        return {
            "ai_enabled": True,
            "error": f"AI analysis failed: {str(e)}",
            "fallback": "Using manual analysis only"
        }


def generate_incident_summary(ai_analysis, postmortem_summary):
    """Generate a human-readable executive summary"""
    
    if not model or not ai_analysis.get("ai_enabled"):
        return None
    
    try:
        prompt = f"""
Create a brief executive summary (3-4 sentences) of this incident for stakeholders:

Primary Cause: {postmortem_summary.get('primary_cause')}
Preventability: {postmortem_summary.get('preventability')}
AI Analysis: {ai_analysis.get('root_cause_explanation', '')}

Make it clear, non-technical, and action-oriented.
"""
        
        response = model.generate_content(prompt)
        return response.text.strip()
    
    except Exception as e:
        print(f"Failed to generate summary: {e}")
        return None


def categorize_incident(timeline, probabilities, explanations):
    """AI-powered automatic incident categorization"""
    
    if not model:
        return {
            "category": "Uncategorized",
            "confidence": 0,
            "tags": []
        }
    
    try:
        prompt = f"""
Analyze this system incident and categorize it.

## Timeline:
{chr(10).join(timeline[:10])}  # First 10 events

## Detected Issues:
{chr(10).join([f"- {k}: {explanations.get(k, '')}" for k, v in probabilities.items() if v > 0])}

Categorize this incident into ONE primary category:
- Database (DB timeouts, connection issues, query failures)
- Network (connectivity, latency, packet loss)
- Human Error (ignored alerts, manual overrides, misconfigurations)
- Performance (CPU, memory, disk, slow response)
- Security (unauthorized access, breaches, suspicious activity)
- Configuration (wrong settings, missing configs)
- Hardware (server failure, disk failure)
- Application (bugs, crashes, exceptions)

Also provide 2-3 relevant tags.

Respond in this format:
CATEGORY: [category name]
CONFIDENCE: [0-100]
TAGS: [tag1], [tag2], [tag3]
"""
        
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        # Parse response
        category = "Uncategorized"
        confidence = 50
        tags = []
        
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith("CATEGORY:"):
                category = line.replace("CATEGORY:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = int(line.replace("CONFIDENCE:", "").strip())
                except:
                    confidence = 50
            elif line.startswith("TAGS:"):
                tag_str = line.replace("TAGS:", "").strip()
                tags = [t.strip() for t in tag_str.split(",")]
        
        return {
            "category": category,
            "confidence": confidence,
            "tags": tags
        }
    
    except Exception as e:
        print(f"Failed to categorize incident: {e}")
        return {
            "category": "Uncategorized",
            "confidence": 0,
            "tags": [],
            "error": str(e)
        }


def query_incidents_ai(user_query, incidents_data):
    """Natural language query interface for incident history"""
    
    if not model:
        return {
            "answer": "AI chatbot is disabled. Please set GEMINI_API_KEY.",
            "ai_enabled": False
        }
    
    try:
        # Prepare incident context (summarize to fit context window)
        incident_summary = []
        for incident in incidents_data[:20]:  # Last 20 incidents
            summary = f"""
Incident ID: {incident.get('id', 'N/A')}
Date: {incident.get('timestamp', 'N/A')}
Category: {incident.get('incident_category', {}).get('category', 'Unknown')}
Primary Cause: {incident.get('postmortem_summary', {}).get('primary_cause', 'Unknown')}
Preventability: {incident.get('postmortem_summary', {}).get('preventability', 'Unknown')}
"""
            incident_summary.append(summary)
        
        context = f"""
You are an intelligent assistant for SysAutopsy, a system failure analysis platform.

User Question: {user_query}

## Recent Incidents Database:
{chr(10).join(incident_summary)}

Answer the user's question based on the incident data above. Be specific and reference incident IDs when relevant.
If the data doesn't contain enough information, say so clearly.
Keep your answer concise (3-5 sentences) and actionable.
"""
        
        response = model.generate_content(context)
        
        return {
            "answer": response.text.strip(),
            "ai_enabled": True,
            "query": user_query,
            "incidents_analyzed": len(incidents_data)
        }
    
    except Exception as e:
        return {
            "answer": f"Error processing query: {str(e)}",
            "ai_enabled": True,
            "error": str(e)
        }
