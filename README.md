# BlackClown : AI-Assisted Tools for RCE Vulnerability Test, Discovery &amp; Exploitation
Created by Armx888
![image](https://github.com/user-attachments/assets/550c6f59-0856-402d-966b-0eca3ac13302)

# 1. Introduction

This security assessment was conducted to evaluate the security posture of the target application using AI-driven vulnerability detection and automated exploit execution. The primary goal was to identify critical vulnerabilities, particularly those leading to Remote Code Execution (RCE), which could grant unauthorized root access to the system.

# 2. Testing Methodology

# 2.1 AI-Based Vulnerability Detection
A custom AI model, leveraging transformers and pre-trained models such as CodeBERT and BART, was used to analyze source code for potential security flaws. The AI model classified vulnerabilities based on severity and likelihood of exploitation.

# 2.2 Automated Exploit Generation
Once a high-probability vulnerability was detected, the system automatically generated a Proof of Concept (PoC) exploit targeting the identified weakness. The exploit was executed in a controlled environment to validate the findings.

# 2.3 Privilege Escalation & Root Access Validation
If Remote Code Execution (RCE) was confirmed, additional tests were performed to determine if privilege escalation to root was possible. AI-assisted post-exploitation scripts analyzed system configurations, extracted sensitive data, and assessed the depth of compromise.

# 3. General AI Explanation
The notebook utilizes AI models, specifically CodeBERT and BART, to analyze source code and detect potential security vulnerabilities. It assigns a probability score to determine how likely a piece of code is to be exploited. If the probability exceeds 98%, it identifies the most critical vulnerability.

# How the AI Works in This Notebook:
  [1]	Loads a pre-trained AI model optimized for code security analysis.
  [2] Processes a given source code snippet to detect vulnerabilities.
  [3] Identifies the most probable security issue and suggests a Proof of Concept (PoC) for exploitation.
  [4] Optionally, executes the PoC in a sandboxed environment for validation.

# Function Overview
  [1]	load_best_model(): Loads and selects the best vulnerability detection model.
  [2]	predict_vulnerability(code_snippet): Predicts how vulnerable a given code snippet is.
  [3]	classify_vulnerability_type(): Determines the most critical vulnerability detected.
  [4]	generate_exploit_poc(vuln_type): Generates an exploit script for testing.
  [5]	execute_exploit(exploit_code): Runs the exploit in a test environment and logs results.

# Steps to Reproduce
  [1]	Run the Notebook to initialize the AI model.
  [2]	Provide a URL containing the source code to be analyzed.
  [3]	The AI will scan the code and calculate the probability of vulnerability.
  [4]	If the probability is ≥98%, the script generates a PoC for the most critical issue.
  [5]	The notebook then generated an RCE PoC, which was executed in a controlled environment to verify the issue.
