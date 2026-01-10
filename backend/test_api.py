import os
import google.generativeai as genai

# Test Gemini API connection
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("❌ GEMINI_API_KEY environment variable not set!")
    print("Set it with: $env:GEMINI_API_KEY='your-key-here'")
    exit(1)

print(f"🔑 API Key found: {api_key[:10]}...{api_key[-4:]}")
print("🔄 Testing Gemini API connection...\n")

try:
    # Configure Gemini
    genai.configure(api_key=api_key)
    
    # List available models
    print("📋 Available models:")
    for model in genai.list_models():
        if 'generateContent' in model.supported_generation_methods:
            print(f"   ✓ {model.name}")
    
    print("\n🧪 Testing text generation...")
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    response = model.generate_content("Say 'API is working!' in a creative way.")
    
    print("✅ SUCCESS! API is working!\n")
    print(f"Response: {response.text}")
    print("\n" + "="*50)
    print("✅ Your Gemini API key is ACTIVE and working!")
    print("✅ No billing required for free tier usage")
    print("✅ Rate limits: 60 req/min, 1500 req/day")
    print("="*50)
    
except Exception as e:
    print(f"❌ ERROR: {e}")
    print("\nPossible issues:")
    print("1. Invalid API key")
    print("2. API key needs to be enabled in Google AI Studio")
    print("3. Network/firewall blocking the request")
    print("4. API quota exceeded")
