"""
One-off smoke test - NOT part of the pipeline.
Confirms GEMINI_API_KEY works with the new google-genai SDK.
"""

import os
from google import genai

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("[ERROR] GEMINI_API_KEY environment variable is not set.")
    exit(1)

client = genai.Client(api_key=api_key)

print("Sending a test message to gemini-flash-latest...\n")
response = client.models.generate_content(
    model="gemini-flash-latest",
    contents="Say hello in one sentence.",
)
print("Response:", response.text)