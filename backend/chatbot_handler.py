"""
AI Chatbot Handler - Conversational Q&A about incident analysis
Uses Gemini to answer user questions about logs and analysis results
"""
import os
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
chat_model = None

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        chat_model = genai.GenerativeModel('gemini-2.5-flash')
    except Exception as e:
        print(f"Chat model initialization failed: {e}")


def answer_question(question, analysis_context):
    """
    Answer user questions about the incident analysis using Gemini
    
    Args:
        question: User's question
        analysis_context: Current analysis data (structured, not raw logs)
    
    Returns:
        AI-generated answer based on analysis context
    """
    
    if not chat_model:
        return "AI chatbot is not available. Please set GEMINI_API_KEY environment variable."
    
    try:
        # Build context from analysis data
        context_prompt = build_context_prompt(analysis_context)
        
        # Create prompt with context + question
        full_prompt = f"""You are an AI assistant helping engineers understand an incident analysis.

ANALYSIS CONTEXT:
{context_prompt}

USER QUESTION: {question}

Provide a clear, concise answer based on the analysis context above. If the question cannot be answered from the available data, say so politely and suggest what information might help.

Keep your answer professional, technical when appropriate, and under 200 words."""

        response = chat_model.generate_content(full_prompt)
        return response.text.strip()
    
    except Exception as e:
        error_msg = str(e)
        
        # Handle rate limit errors specifically
        if "429" in error_msg or "quota" in error_msg.lower() or "rate" in error_msg.lower():
            return """⚠️ **API Rate Limit Reached**

The Gemini API free tier limit has been exceeded (20 requests/day for gemini-2.5-flash).

**Options:**
1. Wait ~30 seconds and try again (rate limit resets)
2. Review the analysis results displayed above - they contain detailed insights
3. Check your analysis sections: Root Causes, Adaptive Analysis, GenAI Explanation

**Tip:** The AI has already analyzed your logs. Most answers can be found in the analysis cards above!"""
        
        return f"Sorry, I encountered an error: {error_msg}"


def build_context_prompt(context):
    """Build structured context string from analysis data"""
    
    if not context:
        return "No analysis context available yet."
    
    parts = []
    
    # Metadata
    if "metadata" in context:
        meta = context["metadata"]
        parts.append(f"INCIDENT: {meta.get('incident_title', 'Unknown')}")
        parts.append(f"SYSTEM: {meta.get('system_name', 'Unknown')}")
        parts.append(f"ENVIRONMENT: {meta.get('environment', 'Unknown')}")
        parts.append(f"SEVERITY: {meta.get('severity', 'Unknown')}")
        parts.append(f"INCIDENT TYPE: {meta.get('incident_type', 'Unknown')}")
    
    # Root causes
    if "probabilities" in context:
        parts.append("\nROOT CAUSE ANALYSIS:")
        for cause, prob in context["probabilities"].items():
            parts.append(f"- {cause}: {prob}%")
    
    # Primary cause
    if "primary_root_cause" in context:
        parts.append(f"\nPRIMARY CAUSE: {context['primary_root_cause']}")
    
    # Risk level
    if "risk_level" in context:
        parts.append(f"RISK LEVEL: {context['risk_level']}")
    
    # Timeline summary
    if "timeline" in context:
        timeline = context["timeline"]
        parts.append(f"\nTIMELINE: {len(timeline)} events logged")
        if timeline:
            parts.append(f"First event: {timeline[0]}")
            if len(timeline) > 1:
                parts.append(f"Last event: {timeline[-1]}")
    
    # Missed intervention
    if "missed_intervention" in context and context["missed_intervention"]:
        parts.append(f"\nMISSED INTERVENTION: {context['missed_intervention'].get('message', 'Yes')}")
    
    # Adaptive analysis
    if "adaptive_analysis" in context:
        adaptive = context["adaptive_analysis"]
        parts.append(f"\nSIMILAR INCIDENTS: {adaptive.get('similar_incidents_found', 0)}")
        if "explanation" in adaptive and isinstance(adaptive["explanation"], list):
            parts.append("\nCONTEXT INSIGHTS:")
            for insight in adaptive["explanation"][:3]:  # First 3 insights
                parts.append(f"- {insight}")
    
    # Postmortem
    if "postmortem_summary" in context:
        pm = context["postmortem_summary"]
        parts.append(f"\nPREVENTABILITY: {pm.get('preventability', 'Unknown')}")
        parts.append(f"RECOMMENDED ACTION: {pm.get('recommended_action', 'None')}")
    
    return "\n".join(parts)


def get_suggested_questions(analysis_context):
    """Generate suggested questions based on analysis context"""
    
    questions = [
        "What was the primary cause of this incident?",
        "How could this incident have been prevented?",
        "What should we do differently next time?"
    ]
    
    if not analysis_context:
        return questions
    
    # Add context-specific questions
    if analysis_context.get("missed_intervention"):
        questions.append("Why was the intervention opportunity missed?")
    
    if analysis_context.get("adaptive_analysis", {}).get("similar_incidents_found", 0) > 0:
        questions.append("What similar incidents happened before?")
    
    if analysis_context.get("risk_level") in ["CRITICAL", "HIGH"]:
        questions.append("What immediate actions should we take?")
    
    if analysis_context.get("timeline"):
        questions.append("Can you explain the timeline of events?")
    
    return questions[:5]  # Return top 5 questions
