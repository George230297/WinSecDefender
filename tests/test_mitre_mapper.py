import pytest
import tempfile
import json
import os
import sys
from unittest.mock import patch, MagicMock

from app.core.mitre_mapper import MitreMapper


@pytest.fixture
def temp_cache():
    # Create a temporary cache file
    fd, path = tempfile.mkstemp(suffix=".json")
    
    mock_data = {
        "T1574.009": {
            "id": "T1574.009",
            "name": "Path Interception by Unquoted Path",
            "description": "Mock description",
            "url": "https://attack.mitre.org/techniques/T1574/009/",
            "deprecated": False,
            "revoked": False
        },
        "T1088": {
            "id": "T1088",
            "name": "Bypass User Account Control [Deprecated]",
            "description": "Deprecated in favor of T1548.002",
            "url": "https://attack.mitre.org/techniques/T1088/",
            "deprecated": True,
            "revoked": True
        }
    }
    
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(mock_data, f)
        
    yield path
    
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


def test_load_cache(temp_cache):
    mapper = MitreMapper(cache_file=temp_cache)
    assert len(mapper.cache) == 2
    assert "T1574.009" in mapper.cache


def test_get_technique_details(temp_cache):
    mapper = MitreMapper(cache_file=temp_cache)
    
    # Valid mapping
    details = mapper.get_technique_details("Unquoted_Services")
    assert details is not None
    assert details["id"] == "T1574.009"
    assert not details["deprecated"]
    
    # Missing finding key
    assert mapper.get_technique_details("Unknown_Finding") is None


def test_deprecated_handling(temp_cache, caplog):
    # Map a finding to the deprecated ID to see how it handles it
    mapper = MitreMapper(cache_file=temp_cache)
    # Monkeypatch for the test
    mapper.FINDING_TO_TECHNIQUE["Old_UAC"] = "T1088"
    
    details = mapper.get_technique_details("Old_UAC")
    assert details is not None
    assert details["deprecated"] is True
    
    # Should log a warning
    assert "deprecated/revoked in MITRE ATT&CK." in caplog.text


def test_enrich_report_dict(temp_cache):
    mapper = MitreMapper(cache_file=temp_cache)
    
    report = {
        "Unquoted_Services": [
            {"service": "vuln_svc", "path": "C:\\Program Files\\vuln svc\\srv.exe"}
        ],
        "System_Config": "OK"
    }
    
    enriched = mapper.enrich_report(report)
    
    assert "mitre_techniques" in enriched
    techniques_list = enriched["mitre_techniques"]
    assert len(techniques_list) == 1
    assert "Unquoted_Services" in techniques_list[0]
    assert techniques_list[0]["Unquoted_Services"]["id"] == "T1574.009"


def test_enrich_report_list(temp_cache):
    mapper = MitreMapper(cache_file=temp_cache)
    
    report = [
        {"Unquoted_Services": "vuln_svc1"},
        {"Unquoted_Services": "vuln_svc2"},
        {"Other": "Safe"}
    ]
    
    enriched = mapper.enrich_report(report)
    assert isinstance(enriched, list)
    assert "mitre_techniques" in enriched[0]
    assert "mitre_techniques" in enriched[1]
    assert "mitre_techniques" not in enriched[2]


@patch("app.core.mitre_mapper.logger")
def test_update_cache_no_attackcti(mock_logger):
    # Missing attackcti testing
    with patch.dict(sys.modules, {'attackcti': None}):
        mapper = MitreMapper(cache_file="dummy.json")
        mapper.update_cache()
        mock_logger.error.assert_called_with("attackcti is not installed. Please install it to update the MITRE cache.")
