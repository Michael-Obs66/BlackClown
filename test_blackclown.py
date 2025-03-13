import pytest
from src.blackclown import predict_vulnerability

def test_predict_vulnerability():
    sample_code = "import os; os.system('rm -rf /')"
    score = predict_vulnerability(sample_code)
    assert 0 <= score <= 1
