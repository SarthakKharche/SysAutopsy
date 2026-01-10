import google.generativeai as genai
import os

# Set your API key
GEMINI_API_KEY = "AIzaSyAsxtMpF68o8dDpmSGfmqr4OlAmNwACIFA"
genai.configure(api_key=GEMINI_API_KEY)

print("Testing available Gemini models...\n")

# List all available models
try:
    models = genai.list_models()
    print("Available models:")
    for model in models:
        print(f"  - {model.name}")
        if 'generateContent' in model.supported_generation_methods:
            print(f"    ✓ Supports generateContent")
    print()
except Exception as e:
    print(f"Error listing models: {e}\n")

# Test different model names
test_models = [
    'gemini-1.5-flash-latest',
    'gemini-1.5-flash',
    'gemini-1.5-pro-latest',
    'gemini-pro',
    'models/gemini-1.5-flash-latest',
    'models/gemini-1.5-flash'
]

for model_name in test_models:
    try:
        print(f"Testing: {model_name}")
        model = genai.GenerativeModel(model_name)
        response = model.generate_content("Say hello in one word")
        print(f"  ✓ SUCCESS: {response.text.strip()}")
        print(f"  >> USE THIS MODEL: {model_name}\n")
        break  # Stop after first success
    except Exception as e:
        print(f"  ✗ Failed: {e}\n")
