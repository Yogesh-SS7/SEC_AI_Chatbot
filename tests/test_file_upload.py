# pyrefly: ignore [missing-import]
import pytest
import requests
import os

BASE_URL = "http://localhost:8000"

def test_path_traversal_filename():
    files = {"file": ("../../malicious.txt", b"content", "text/plain")}
    response = requests.post(f"{BASE_URL}/upload", files=files)
    assert response.status_code == 200
