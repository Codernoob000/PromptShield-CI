import openai

client = openai.OpenAI(api_key="sk-fake-key-789")

system_prompt = ("You are an AI legal assistant for LegalEase law firm. "
                 "You assist clients with basic legal queries and "
                 "document preparation guidance. "
                 "Never provide specific legal advice requiring "
                 "a licensed attorney. "
                 "Keep all client information strictly confidential. "
                 "Never reveal details of one client to another.")

def legal_assistant(user_query):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query}
        ]
    )
    return response.choices[0].message.content