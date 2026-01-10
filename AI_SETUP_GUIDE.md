# 🤖 AI Integration Setup Guide

## Get Your FREE Gemini API Key

1. Visit: **https://makersuite.google.com/app/apikey**
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy your API key

## Set the API Key (Windows PowerShell)

```powershell
# Temporary (current session only)
$env:GEMINI_API_KEY='your-api-key-here'

# Permanent (add to PowerShell profile)
[System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', 'your-api-key-here', 'User')
```

## What the AI Does

✅ **Intelligent Root Cause Analysis**
- Natural language explanation of failures
- Context-aware insights beyond pattern matching
- Technical root cause with plain language

✅ **Smart Prevention Recommendations**
- 3 specific, actionable steps to prevent recurrence
- Tailored to your specific failure scenario
- Implementation-ready suggestions

✅ **Risk Assessment**
- What happens if this pattern repeats
- Impact analysis and urgency evaluation

✅ **Executive Summary**
- Non-technical summary for stakeholders
- Clear, action-oriented language

## Test It

```bash
cd backend
python app.py
```

Upload a log file and check the analysis response - you'll see new fields:
- `ai_analysis` - AI-generated insights
- `executive_summary` - Stakeholder-friendly summary

## Free Tier Limits

- **60 requests per minute**
- **1,500 requests per day**
- Completely FREE forever for these limits!

Perfect for your use case! 🎉
