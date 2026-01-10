import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

if not firebase_admin._apps:
    # Check if running with environment variable (production) or file (development)
    firebase_credentials = os.environ.get('FIREBASE_CREDENTIALS')
    
    if firebase_credentials:
        # Production: Load from environment variable (JSON string)
        cred_dict = json.loads(firebase_credentials)
        cred = credentials.Certificate(cred_dict)
    else:
        # Development: Load from file
        cred = credentials.Certificate("firebase_key.json")
    
    firebase_admin.initialize_app(cred)

db = firestore.client()
