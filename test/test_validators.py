import pytest
from fastapi import HTTPException
from mcp_server.app import validate_ip, validate_domain, validate_hash, validate_cve

def test_validate_ip_ok():
    assert validate_ip("8.8.8.8") == "8.8.8.8"

def test_validate_ip_bad():
    with pytest.raises(HTTPException):
        validate_ip("999.999.999.999")

def test_validate_domain_ok():
    assert validate_domain("Example.com") == "example.com"

def test_validate_domain_bad():
    with pytest.raises(HTTPException):
        validate_domain("-bad-domain.com")

def test_validate_hash_ok_md5():
    assert validate_hash("44d88612fea8a8f36de82e1278abb02f")

def test_validate_hash_bad():
    with pytest.raises(HTTPException):
        validate_hash("not-a-hash")

def test_validate_cve_ok():
    assert validate_cve("cve-2021-44228") == "CVE-2021-44228"

def test_validate_cve_bad():
    with pytest.raises(HTTPException):
        validate_cve("2021-44228")