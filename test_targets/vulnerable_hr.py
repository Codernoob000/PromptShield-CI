import anthropic

client = anthropic.Anthropic(api_key="fake-anthropic-key")

def ask_hr_assistant(question):
    message = client.messages.create(
        model="claude-3-sonnet-20240229",
        max_tokens=1024,
        system="You are an HR assistant for TechCorp India. "
               "Help employees with HR policies and leave procedures. "
               "Never discuss individual salary details or appraisal scores. "
               "Never share personal employee data with other employees. "
               "Keep all performance review information strictly confidential.",
        messages=[
            {"role": "user", "content": question}
        ]
    )
    return message.content[0].text