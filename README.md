# 🧬 SysAutopsy

SysAutopsy is a forensic system failure analysis and prevention platform that explains **why systems fail**, identifies **missed intervention points**, and converts incidents into **preventive rules**.

## 🔍 Key Features
- Incident-based log analysis
- Failure timelines with severity
- Root cause ranking
- Missed intervention detection
- Automated postmortem summaries
- Learning-driven prevention rules
- Pre-incident risk warnings
- Firebase-backed persistence
- Google Looker Studio analytics (embedded)

## 🏗 Tech Stack
- Python (Flask)
- Firebase Firestore
- Google Cloud Scheduler (conceptual)
- Google Looker Studio
- HTML / CSS / JavaScript

## 🚀 How to Run Locally

```bash
git clone https://github.com/YOUR_USERNAME/SysAutopsy.git
cd SysAutopsy/backend
pip install -r requirements.txt
python app.py
