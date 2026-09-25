import google.generativeai as genai

genai.configure(api_key="fake-gemini-key")

model = genai.GenerativeModel(
    model_name="gemini-pro",
    system_instruction="You are a customer support agent for ShopEasy. "
                       "Help customers track orders and process returns. "
                       "Never reveal internal pricing strategies. "
                       "Never share supplier information with customers. "
                       "Do not provide discounts beyond 10 percent "
                       "without manager approval."
)

def handle_customer_query(query):
    chat = model.start_chat()
    response = chat.send_message(query)
    return response.text