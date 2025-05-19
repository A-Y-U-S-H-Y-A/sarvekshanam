import os

# Application configuration
UPLOAD_FOLDER = "uploaded_files"
DIR = os.getenv("DIR")

# API configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL_NAME = "llama3-70b-8192"

# LLM configuration
TEMPERATURE = 0

# Chat prompt template
CHAT_TEMPLATE = """
You are a AI assistant.

Here is the conversation History: {context}

Question: {question}

Answer:
"""
