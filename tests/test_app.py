import unittest
from fastapi.testclient import TestClient
from backend.app.main import app

class TestSecureTradingPlatform(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
    
    def test_read_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_static_files(self):
        # Test that static files endpoint exists
        response = self.client.get("/static/nonexistent.css")
        # This should return 404 since the file doesn't exist
        # but the endpoint should be available
        self.assertEqual(response.status_code, 404)

if __name__ == "__main__":
    unittest.main()