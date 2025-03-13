import pytest
from src.blackclown import predict_vulnerability

def test_predict_vulnerability():
    sample_code = "SELECT * FROM users WHERE username='admin';"
    score = predict_vulnerability(sample_code)
    assert 0 <= score <= 1 
