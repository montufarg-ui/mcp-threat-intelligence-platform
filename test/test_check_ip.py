from fastapi.testclient import TestClient
from mcp_server.app import app

client = TestClient(app)

class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload

def test_check_ip_ok(monkeypatch):
    # mock requests.get used in check_ip
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResp(
            200,
            {
                "data": {
                    "abuseConfidenceScore": 10,
                    "countryCode": "US",
                    "isp": "ExampleISP",
                    "domain": "example.net",
                    "totalReports": 1,
                    "lastReportedAt": "2026-01-01T00:00:00Z"
                }
            }
        )

    import mcp_server.app as mod
    monkeypatch.setattr(mod.requests, "get", fake_get)
    # also ensure API key exists for test
    monkeypatch.setattr(mod, "ABUSEIPDB_API_KEY", "testkey")

    r = client.post("/tools/check_ip", json={"ip": "8.8.8.8"})
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == "8.8.8.8"
    assert data["risk"] == "low"
    assert data["abuseConfidenceScore"] == 10