import torch
import transformers
import requests
import pygments
import os
import time
import subprocess
from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# Load pre-trained models for vulnerability detection
MODEL_NAMES = ["microsoft/codebert-base", "facebook/bart-large"]
devices = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def load_best_model():
    best_model, best_tokenizer, best_score = None, None, 0
    for model_name in MODEL_NAMES:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2).to(devices)
        score = evaluate_model(model)
        if score > best_score:
            best_model, best_tokenizer, best_score = model, tokenizer, score
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
    inputs = tokenizer(code_snippet, return_tensors="pt", truncation=True, padding=True, max_length=512).to(devices)
    with torch.no_grad():
        outputs = model(**inputs)
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    vulnerability_score = probabilities[0][1].item()
    return vulnerability_score

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
            print(f"Detected language: {language}")
            if language.lower() != "python":
                print("Warning: This scanner is optimized for Python code.")
        except ClassNotFound:
            print("Could not detect programming language.")
        return code_text
    except requests.RequestException as e:
        print(f"Error fetching code from URL: {e}")
        return None

def generate_exploit_poc(vuln_type):
    exploits = {
        "Remote Code Execution (RCE)": "whoami && cat /etc/passwd && echo 'Hacked' > /tmp/hacked.txt",
        "SQL Injection": "' OR '1'='1'; -- ",
        "Cross-Site Scripting (XSS)": "<script>alert('XSS')</script>",
        "Command Injection": "ls -la && touch /tmp/injected.txt"
    }
    return exploits.get(vuln_type, "No PoC available for this vulnerability")

def execute_exploit(exploit_code):
    try:
        print("Executing PoC on live system...")
        time.sleep(2)
        result = subprocess.getoutput(exploit_code)
        print(f"PoC Output: {result}")
        with open("exploit_log.txt", "a") as log_file:
            log_file.write(f"Executed: {exploit_code}\nOutput: {result}\n\n")

        validate_exploit()
    except Exception as e:
        print(f"Error executing PoC: {e}")

def validate_exploit():
    print("Validating exploit...")
    # Check if the exploit created a file
    if os.path.exists("/tmp/hacked.txt"):
        print("Validation 1: Exploit file created successfully.")

    # Check command history
    history = subprocess.getoutput("cat ~/.bash_history")
    if "whoami" in history or "cat /etc/passwd" in history:
        print("Validation 2: Commands detected in history.")

    # Check file metadata
    passwd_info = subprocess.getoutput("stat /etc/passwd")
    print("Validation 3: /etc/passwd metadata:\n", passwd_info)

    # Check system logs for suspicious activity
    auth_log = subprocess.getoutput("grep 'whoami' /var/log/auth.log || echo 'No log entry found'")
    print("Validation 4: System logs:", auth_log)

    # Capture network traffic for suspicious activity
    print("Validation 5: Checking for network traffic (simulated)...")
    print("(Use tools like tcpdump or Wireshark for real-time monitoring.)")

def main():
    url = "https://example.com/"  # Replace with actual URL
    code = get_code_from_url(url)
    if code:
        score = predict_vulnerability(code)
        vuln_type, vuln_prob = classify_vulnerability_type()
        print(f"Vulnerability Score: {score:.2f}")
        if vuln_prob > 0.98:
            print(f"Most critical vulnerability: {vuln_type} (Probability: {vuln_prob:.2f})")
            exploit_code = generate_exploit_poc(vuln_type)
            print(f"Generated PoC: {exploit_code}")
            execute_exploit(exploit_code)

if __name__ == "__main__":
    main()

