# Threat Intelligence MCP Server — Demo

## Run
uvicorn mcp_server.app:app --reload --port 8001

## Health
curl http://127.0.0.1:8001/health

## IP reputation
curl -X POST http://127.0.0.1:8001/tools/check_ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'

## Hash scan
curl -X POST http://127.0.0.1:8001/tools/scan_hash \
  -H "Content-Type: application/json" \
  -d '{"hash":"44d88612fea8a8f36de82e1278abb02f"}'

## Domain lookup
curl -X POST http://127.0.0.1:8001/tools/lookup_domain \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com"}'

## CVE details
curl -X POST http://127.0.0.1:8001/tools/get_cve_details \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-44228"}'

## Correlate IOCs
curl -X POST http://127.0.0.1:8001/tools/correlate_iocs \
  -H "Content-Type: application/json" \
  -d '{"iocs":["8.8.8.8","google.com","CVE-2021-44228"]}'
