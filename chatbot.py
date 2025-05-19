import json
import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from config import GROQ_API_KEY, GROQ_MODEL_NAME, TEMPERATURE, CHAT_TEMPLATE

# Initialize the chat model
chat = ChatGroq(
    temperature=TEMPERATURE, 
    groq_api_key=GROQ_API_KEY, 
    model_name=GROQ_MODEL_NAME
)

# Create the chat chain
prompt = ChatPromptTemplate.from_template(CHAT_TEMPLATE)
chain = prompt | chat

# Global variables
cookie_return = False
report_gen = False

def generate_initial_context(context=None):
    """Generate the initial context for the chat"""
    default_modules = "XSS, InfoScanner, SQLi, SSL, WebScanner, DNS, Misc, Pathfinders, Assetfinder"
    modules = context if context is not None else default_modules

    return f"""
    First, ask the user to enter the URL of the site. Only after the user provides the URL, ask them to choose one or more modules from the following options by name: {modules}.
    
    Once both the URL and module options are collected, perform the scan.

    After the tool generates output and sends the report to the user, allow them to interact with and understand the results provided.
    """


# Initialize with starting context
current_context = generate_initial_context()

def reset_chat_context(context=None):
    """Reset the chat context to the initial state"""
    global cookie_return, report_gen
    

    reset_context = generate_initial_context(context)
    cookie_return = False
    report_gen = False
    
    return json.dumps({
        "status": "success", 
        "message": "Chat context reset",
        "context": reset_context
    })

def set_context(new_context):
    """Set the chat context explicitly (used after final report generation)."""
    print("[DEBUG] Chat context has been updated with final report.")
    return json.dumps({
        "status": "success", 
        "message": "Chat context updated",
        "context": new_context
    })

def get_chat_qna(text, context=None):
    """Get the current chat context and Q&A"""
    # Use the provided context or fall back to global if none provided
    chat_context = context if context is not None else current_context
    
    result = chain.invoke({"context": chat_context, "question": text})
    
    # Update context with the new interaction
    updated_context = chat_context + f"\nUser: {text}\nAI: {result.content}"
    
    return json.dumps({
        "context": updated_context, 
        "response": result.content
    })

def get_chat_response(text, context=None):
    """Process user input and generate AI response"""
    global report_gen, cookie_return
    
    # Use the provided context or fall back to global if none provided
    chat_context = context if context is not None else current_context

    user_input = text
    # Get the initial AI response to the user's input
    result = chain.invoke({"context": chat_context, "question": user_input})
    
    # Update the conversation context with the user's input and the AI's initial response
    updated_context = chat_context + f"\nUser: {user_input}\nAI: {result.content}"
    print("\n[DEBUG] Current Context (after initial AI response):\n", updated_context)

    # Define the prompt template for extracting URL and options
    extraction_prompt_template = """
                For the Following text extract the following information given by the user and not AI URL and option (should be the module names) (if not found return null for the value of the key, e.g., "URL": null)
                Format the output as a single JSON object with the following keys:
                URL
                options
                
                text: {text_to_process} 
                
                Only give the JSON object as the output. For example:
                {{"URL": "http://example.com", "options": ["XSS", "SQLi"]}}
                or if options are not found:
                {{"URL": "http://example.com", "options": null}}
                """
    
    # Format the extraction prompt with the user's latest input
    formatted_extraction_prompt = extraction_prompt_template.format(text_to_process=user_input)
    
    print(f"\n[DEBUG] Formatted Extraction Prompt (Question for LLM):\n{formatted_extraction_prompt}")
        
    # Invoke the LLM to extract information using the formatted prompt
    dictt_str = chain.invoke({"context": updated_context, "question": formatted_extraction_prompt}).content
    print(f"\n[DEBUG] Raw extraction output (dictt_str):\n{dictt_str}")
    
    # Attempt to parse the JSON output from the LLM
    extracted_data = None
    try:
        # The LLM might wrap the JSON in markdown (```json ... ```) or add other text.
        # Try to find the JSON blob.
        match = re.search(r"\{.*\}", dictt_str, re.DOTALL)
        if match:
            cleaned_json_str = match.group(0)
            extracted_data = json.loads(cleaned_json_str)
        else:
            # If no clear JSON blob is found with regex, try to parse the whole string.
            extracted_data = json.loads(dictt_str) 
        
        print(f"\n[DEBUG] Parsed extracted_data:\n{extracted_data}")

    except json.JSONDecodeError as e:
        print(f"\n[DEBUG] JSONDecodeError parsing extracted dictt_str: {e}. Raw string was: {dictt_str}")
        # If parsing fails, return the original AI response in JSON format
        return json.dumps({
            "status": "fallback", 
            "response": result.content,
            "context": updated_context
        })

    # Check if URL and options are present and valid in the parsed output
    if extracted_data and isinstance(extracted_data, dict):
        extracted_url = extracted_data.get("URL")
        extracted_options_raw = extracted_data.get("options")

        # Validate URL
        if not extracted_url or not isinstance(extracted_url, str):
            print(f"\n[DEBUG] URL not found or invalid in extracted data: {extracted_url}")
            return json.dumps({
                "status": "fallback", 
                "response": result.content,
                "context": updated_context
            })

        # Validate and process options
        # Options should be a list of strings. LLM might return null, a string, or a list.
        final_options = []
        if extracted_options_raw is None:
            print(f"\n[DEBUG] Options are null. Proceeding without modules if that's intended, or failing.")
            pass # final_options remains empty
        elif isinstance(extracted_options_raw, str):
            # If options is a non-empty string, split by comma and strip spaces
            final_options = [opt.strip() for opt in extracted_options_raw.split(',') if opt.strip()]
        elif isinstance(extracted_options_raw, list):
            final_options = [str(opt).strip() for opt in extracted_options_raw if str(opt).strip()]
        else:
            print(f"\n[DEBUG] Options format is unrecognized: {extracted_options_raw}")
            return json.dumps({
                "status": "fallback", 
                "response": result.content,
                "context": updated_context
            })

        # If after processing, there are no valid options, but options were expected/required:
        if not final_options:
             print(f"\n[DEBUG] No valid options were extracted or processed.")
        
        print(f"\n[DEBUG] Successfully extracted! URL: {extracted_url}, Options: {final_options}")
        
        if len(final_options) == 0:
            return json.dumps({
                "status": "fallback", 
                "response": result.content,
                "context": updated_context
            })
        
        cookie_return = True # This global variable's usage is outside this function's direct logic
        
        # Return structured JSON with extracted data
        return json.dumps({
            "status": "success", 
            "url": extracted_url, 
            "modules": final_options,
            "context": updated_context
        })

    else:
        if extracted_data:
            print(f"\n[DEBUG] Extraction condition not met. Extracted data: {extracted_data}")
        else:
             print(f"\n[DEBUG] Extraction failed: extracted_data is None or not a dict after parsing.")
        return json.dumps({
            "status": "fallback", 
            "response": result.content,
            "context": updated_context
        })

def parse_output(text):
    """Parse structured output from LLM response"""
    url_schema = ResponseSchema(
        name="URL",
        description="Get the URL provided by the user. If this information is not found, output -1."
    )
    
    option_schema = ResponseSchema(
        name="options",
        description="Extract the options provided by user, and output them as a comma separated Python list. If this information is not found, output []"
    )

    response_schemas = [url_schema, option_schema]
    output_parser = StructuredOutputParser.from_response_schemas(response_schemas)

    try:
        output_dict = output_parser.parse(text)
        # Convert to proper JSON format
        return json.dumps({
            "URL": output_dict.get("URL", "-1"),
            "options": output_dict.get("options", [])
        })
    except Exception as e:
        print(f"Error parsing output: {e}")
        return json.dumps({"URL": "-1", "options": []})
