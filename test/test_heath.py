from fastapi.testclient import TestClient
from mcp_server.app import app

client = TestClient(app)

def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "Threat Intelligence MCP Server" in data["service"]