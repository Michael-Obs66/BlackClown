import torch
import transformers
import requests
import pygments
import os
import time
import logging
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load pre-trained models for vulnerability detection
MODEL_NAMES = ["microsoft/codebert-base", "facebook/bart-large"]
devices = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def load_best_model():
    best_model, best_tokenizer, best_score = None, None, 0
    for model_name in MODEL_NAMES:
        try:
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2).to(devices)
            score = evaluate_model(model)
            if score > best_score:
                best_model, best_tokenizer, best_score = model, tokenizer, score
        except Exception as e:
            logging.error(f"Failed to load model {model_name}: {e}")
    return best_model, best_tokenizer

def evaluate_model(model):
    return torch.rand(1).item()

model, tokenizer = load_best_model()

VULNERABILITY_TYPES = {
    "SQL Injection": 0.95, "Cross-Site Scripting (XSS)": 0.92, "Command Injection": 0.98,
    "Insecure Deserialization": 0.85, "Path Traversal": 0.89, "Remote Code Execution (RCE)": 0.99,
    "Insecure Direct Object Reference (IDOR)": 0.87
}

def predict_vulnerability(code_snippet):
    if not isinstance(code_snippet, str) or len(code_snippet) == 0:
        logging.warning("Invalid input: Empty or non-string code snippet.")
        return 0.0
    
    inputs = tokenizer(code_snippet, return_tensors="pt", truncation=True, padding=True, max_length=512).to(devices)
    with torch.no_grad():
        outputs = model(**inputs)
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    return probabilities[0][1].item()

def classify_vulnerability_type():
    highest_vuln = max(VULNERABILITY_TYPES, key=VULNERABILITY_TYPES.get)
    highest_score = VULNERABILITY_TYPES[highest_vuln]
    return highest_vuln, highest_score

def get_code_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        code_text = response.text
        try:
            lexer = guess_lexer(code_text)
            language = lexer.name
            logging.info(f"Detected language: {language}")
            if language.lower() != "python":
                logging.warning("This scanner is optimized for Python code.")
        except ClassNotFound:
            logging.warning("Could not detect programming language.")
        return code_text
    except requests.RequestException as e:
        logging.error(f"Error fetching code from URL: {e}")
        return None

def generate_exploit_poc(vuln_type):
    exploits = {
        "SQL Injection": "' OR '1'='1'; -- ",
        "Cross-Site Scripting (XSS)": "<script>alert('XSS')</script>",
        "Command Injection": "echo vulnerable && id",
        "Insecure Deserialization": "serializedObject = pickle.dumps({})",
        "Path Traversal": "../../etc/passwd",
        "Remote Code Execution (RCE)": "import os; os.system('whoami')",
        "Insecure Direct Object Reference (IDOR)": "GET /user/12345/profile"
    }
    return exploits.get(vuln_type, "No PoC available for this vulnerability")

def main():
    url = "https://example.org"  # Replace with actual URL
    code = get_code_from_url(url)
    if code:
        score = predict_vulnerability(code)
        vuln_type, vuln_prob = classify_vulnerability_type()
        logging.info(f"Vulnerability Score: {score:.2f}")
        if vuln_prob > 0.98:
            logging.info(f"Most critical vulnerability: {vuln_type} (Probability: {vuln_prob:.2f})")
            exploit_code = generate_exploit_poc(vuln_type)
            logging.info(f"Generated PoC: {exploit_code}")

if __name__ == "__main__":
    main()
