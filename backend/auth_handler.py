"""
Authentication Handler - User login/registration with Firebase Auth
"""
import hashlib
import secrets
import requests
from datetime import datetime
from firebase_config import db

# reCAPTCHA Secret Key - Replace with your actual secret key from Google reCAPTCHA console
RECAPTCHA_SECRET_KEY = "6Lfk8UUsAAAAAIZJbcKqHylSu7mvJaxpBJ3WeZF7"


def verify_recaptcha(token):
    """Verify reCAPTCHA token with Google"""
    if RECAPTCHA_SECRET_KEY == "YOUR_RECAPTCHA_SECRET_KEY":
        # Skip verification during development if no key is set
        print("Warning: reCAPTCHA secret key not configured, skipping verification")
        return True
    
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': token
            }
        )
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA verification error: {e}")
        return False


def hash_password(password, salt=None):
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt, hashed.hex()


def verify_password(password, salt, hashed):
    """Verify password against stored hash"""
    _, new_hash = hash_password(password, salt)
    return new_hash == hashed


def register_user(name, email, password):
    """Register a new user"""
    try:
        # Check if user already exists
        users_ref = db.collection("users")
        existing = users_ref.where("email", "==", email.lower()).limit(1).stream()
        
        if any(existing):
            return {"success": False, "error": "Email already registered"}
        
        # Hash password
        salt, hashed = hash_password(password)
        
        # Create user document
        user_data = {
            "name": name,
            "email": email.lower(),
            "password_hash": hashed,
            "password_salt": salt,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        doc_ref = users_ref.add(user_data)
        user_id = doc_ref[1].id
        
        return {
            "success": True,
            "user": {
                "id": user_id,
                "name": name,
                "email": email.lower()
            }
        }
        
    except Exception as e:
        print(f"Registration error: {e}")
        return {"success": False, "error": "Registration failed. Please try again."}


def login_user(email, password):
    """Authenticate user"""
    try:
        users_ref = db.collection("users")
        users = users_ref.where("email", "==", email.lower()).limit(1).stream()
        
        user_doc = None
        for doc in users:
            user_doc = doc
            break
        
        if not user_doc:
            return {"success": False, "error": "Invalid email or password"}
        
        user_data = user_doc.to_dict()
        
        # Verify password
        if not verify_password(password, user_data["password_salt"], user_data["password_hash"]):
            return {"success": False, "error": "Invalid email or password"}
        
        return {
            "success": True,
            "user": {
                "id": user_doc.id,
                "name": user_data.get("name", ""),
                "email": user_data["email"]
            }
        }
        
    except Exception as e:
        print(f"Login error: {e}")
        return {"success": False, "error": "Login failed. Please try again."}


def get_user_by_id(user_id):
    """Get user by ID"""
    try:
        doc = db.collection("users").document(user_id).get()
        if doc.exists:
            data = doc.to_dict()
            return {
                "id": doc.id,
                "name": data.get("name", ""),
                "email": data["email"]
            }
        return None
    except Exception as e:
        print(f"Get user error: {e}")
        return None


def google_auth_user(email, name):
    """Authenticate or register user via Google OAuth"""
    try:
        users_ref = db.collection("users")
        existing = users_ref.where("email", "==", email.lower()).limit(1).stream()
        
        user_doc = None
        for doc in existing:
            user_doc = doc
            break
        
        if user_doc:
            # User exists, return their info
            user_data = user_doc.to_dict()
            return {
                "success": True,
                "user": {
                    "id": user_doc.id,
                    "name": user_data.get("name", name),
                    "email": user_data["email"]
                }
            }
        else:
            # Create new user (no password for Google users)
            user_data = {
                "name": name or email.split('@')[0],
                "email": email.lower(),
                "auth_provider": "google",
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            doc_ref = users_ref.add(user_data)
            user_id = doc_ref[1].id
            
            return {
                "success": True,
                "user": {
                    "id": user_id,
                    "name": user_data["name"],
                    "email": email.lower()
                }
            }
            
    except Exception as e:
        print(f"Google auth error: {e}")
        return {"success": False, "error": "Google authentication failed"}
