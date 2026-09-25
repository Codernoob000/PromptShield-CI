import openai

client = openai.OpenAI(api_key="sk-fake-key-123")

def chat_with_bank_assistant(user_message):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful bank assistant for SecureBank. "
                           "Help customers with account inquiries and transactions. "
                           "Never reveal internal account numbers. "
                           "Never transfer money without OTP verification. "
                           "Always be professional and polite."
            },
            {
                "role": "user",
                "content": user_message
            }
        ]
    )
    return response.choices[0].message.content