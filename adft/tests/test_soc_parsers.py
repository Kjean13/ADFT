"""Tests for SOC multi-format parsers."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write(content: str, suffix: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(content)
    f.flush()
    f.close()
    return Path(f.name)


# ---------------------------------------------------------------------------
# YAML Parser
# ---------------------------------------------------------------------------

class TestYamlParser:
    def test_yaml_list(self):
        from adft.core.ingestion.soc_parsers import YamlParser
        p = YamlParser()
        path = _write("- EventID: 4625\n  User: bob\n- EventID: 4624\n  User: alice\n", ".yaml")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 2
        assert events[0]["EventID"] == 4625
        assert events[0]["_parser"] == p.parser_name

    def test_yaml_dict_wrapper(self):
        from adft.core.ingestion.soc_parsers import YamlParser
        p = YamlParser()
        content = "events:\n  - EventID: 4672\n    User: admin\n"
        path = _write(content, ".yml")
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["EventID"] == 4672

    def test_yaml_sigma_rule(self):
        from adft.core.ingestion.soc_parsers import YamlParser
        p = YamlParser()
        content = (
            "title: Brute Force Detection\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4625\n"
            "level: high\n"
        )
        path = _write(content, ".yml")
        events = p.parse(path)
        assert len(events) == 1
        assert events[0].get("_sigma_rule") is True
        assert events[0]["title"] == "Brute Force Detection"

    def test_yml_not_parsed_as_json(self):
        from adft.core.ingestion.soc_parsers import YamlParser
        p = YamlParser()
        path = _write("[1, 2, 3]", ".txt")
        assert not p.can_parse(path)


# ---------------------------------------------------------------------------
# CSV Parser
# ---------------------------------------------------------------------------

class TestCsvParser:
    def test_csv_basic(self):
        from adft.core.ingestion.soc_parsers import CsvParser
        p = CsvParser()
        content = "EventID,User,Timestamp\n4625,bob,2026-01-15T10:00:00Z\n4624,alice,2026-01-15T10:01:00Z\n"
        path = _write(content, ".csv")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 2
        assert events[0]["EventID"] == 4625

    def test_tsv_basic(self):
        from adft.core.ingestion.soc_parsers import CsvParser
        p = CsvParser()
        content = "EventID\tUser\tTimestamp\n4625\tbob\t2026-01-15T10:00:00Z\n"
        path = _write(content, ".tsv")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 1

    def test_csv_column_mapping(self):
        from adft.core.ingestion.soc_parsers import CsvParser
        p = CsvParser()
        content = "_time,hostname,username,src_ip\n2026-01-15T10:00:00Z,DC01,bob,10.0.0.5\n"
        path = _write(content, ".csv")
        events = p.parse(path)
        assert events[0].get("TimeCreated") == "2026-01-15T10:00:00Z"
        assert events[0].get("Computer") == "DC01"
        assert events[0].get("TargetUserName") == "bob"


# ---------------------------------------------------------------------------
# CEF Parser
# ---------------------------------------------------------------------------

class TestCefParser:
    def test_cef_line(self):
        from adft.core.ingestion.soc_parsers import CefParser
        p = CefParser()
        content = 'CEF:0|Vendor|Product|1.0|100|Login Failed|7|src=10.0.0.5 duser=bob dhost=DC01 rt=2026-01-15T10:00:00Z\n'
        path = _write(content, ".cef")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["IpAddress"] == "10.0.0.5"
        assert events[0]["TargetUserName"] == "bob"
        assert events[0]["Computer"] == "DC01"
        assert events[0]["EventID"] == 100

    def test_cef_in_log_file(self):
        from adft.core.ingestion.soc_parsers import CefParser
        p = CefParser()
        content = 'CEF:0|Test|FW|1.0|200|Allowed|3|src=192.168.1.1 dst=10.0.0.1\n'
        path = _write(content, ".log")
        assert p.can_parse(path)

    def test_non_cef_log(self):
        from adft.core.ingestion.soc_parsers import CefParser
        p = CefParser()
        path = _write("just a normal log line\n", ".log")
        assert not p.can_parse(path)


# ---------------------------------------------------------------------------
# LEEF Parser
# ---------------------------------------------------------------------------

class TestLeefParser:
    def test_leef_line(self):
        from adft.core.ingestion.soc_parsers import LeefParser
        p = LeefParser()
        content = 'LEEF:1.0|IBM|QRadar|1.0|100|src=10.0.0.5\tusrName=bob\tdstHostName=DC01\tdevTime=2026-01-15T10:00:00Z\n'
        path = _write(content, ".leef")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["TargetUserName"] == "bob"


# ---------------------------------------------------------------------------
# XML Parser
# ---------------------------------------------------------------------------

class TestXmlEventParser:
    def test_xml_event(self):
        from adft.core.ingestion.soc_parsers import XmlEventParser
        p = XmlEventParser()
        content = (
            '<?xml version="1.0"?>\n'
            '<Events>\n'
            '  <Event>\n'
            '    <System>\n'
            '      <EventID>4625</EventID>\n'
            '      <TimeCreated SystemTime="2026-01-15T10:00:00Z"/>\n'
            '      <Computer>DC01</Computer>\n'
            '    </System>\n'
            '    <EventData>\n'
            '      <Data Name="TargetUserName">bob</Data>\n'
            '      <Data Name="IpAddress">10.0.0.5</Data>\n'
            '    </EventData>\n'
            '  </Event>\n'
            '</Events>\n'
        )
        path = _write(content, ".xml")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["EventID"] == 4625
        assert events[0]["TargetUserName"] == "bob"

    def test_non_event_xml(self):
        from adft.core.ingestion.soc_parsers import XmlEventParser
        p = XmlEventParser()
        path = _write('<root><item>hello</item></root>', ".xml")
        assert not p.can_parse(path)  # no <Event in first 512 bytes


# ---------------------------------------------------------------------------
# Syslog Parser
# ---------------------------------------------------------------------------

class TestSyslogParser:
    def test_rfc3164(self):
        from adft.core.ingestion.soc_parsers import SyslogParser
        p = SyslogParser()
        content = '<134>Jan 15 10:00:00 fw01 sshd[1234]: Failed password for bob from 10.0.0.5\n'
        path = _write(content, ".syslog")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["Computer"] == "fw01"
        assert "Failed password" in events[0]["Message"]

    def test_rfc5424(self):
        from adft.core.ingestion.soc_parsers import SyslogParser
        p = SyslogParser()
        content = '<165>1 2026-01-15T10:00:00Z router01 app 1234 ID1 [meta key=\"val\"] Auth failure\n'
        path = _write(content, ".syslog")
        events = p.parse(path)
        assert len(events) == 1
        assert events[0]["Computer"] == "router01"

    def test_non_syslog(self):
        from adft.core.ingestion.soc_parsers import SyslogParser
        p = SyslogParser()
        path = _write("normal text log\n", ".log")
        assert not p.can_parse(path)


# ---------------------------------------------------------------------------
# Markdown Table Parser
# ---------------------------------------------------------------------------

class TestMarkdownTableParser:
    def test_md_table(self):
        from adft.core.ingestion.soc_parsers import MarkdownTableParser
        p = MarkdownTableParser()
        content = (
            "# Investigation Report\n\n"
            "| Event ID | User | Host | Timestamp |\n"
            "|---|---|---|---|\n"
            "| 4625 | bob | DC01 | 2026-01-15T10:00:00Z |\n"
            "| 4624 | alice | DC01 | 2026-01-15T10:01:00Z |\n"
        )
        path = _write(content, ".md")
        assert p.can_parse(path)
        events = p.parse(path)
        assert len(events) == 2
        assert events[0]["EventID"] == 4625
        assert events[0].get("TargetUserName") == "bob"

    def test_md_no_table(self):
        from adft.core.ingestion.soc_parsers import MarkdownTableParser
        p = MarkdownTableParser()
        path = _write("# Just a heading\n\nSome text.\n", ".md")
        assert not p.can_parse(path)


# ---------------------------------------------------------------------------
# LogLoader integration
# ---------------------------------------------------------------------------

class TestLogLoaderIntegration:
    def test_all_parsers_registered(self):
        from adft.core.ingestion.loader import LogLoader
        loader = LogLoader()
        names = loader.registered_parsers
        assert len(names) >= 9
        assert any("EVTX" in n for n in names)
        assert any("JSON" in n for n in names)
        assert any("YAML" in n for n in names)
        assert any("CSV" in n for n in names)
        assert any("CEF" in n for n in names)
        assert any("LEEF" in n for n in names)
        assert any("XML" in n for n in names)
        assert any("Syslog" in n for n in names)
        assert any("Markdown" in n for n in names)

    def test_loader_csv_file(self):
        from adft.core.ingestion.loader import LogLoader
        loader = LogLoader()
        content = "EventID,User,Timestamp\n4625,bob,2026-01-15T10:00:00Z\n"
        path = _write(content, ".csv")
        events = loader.load(path)
        assert len(events) == 1
        assert events[0]["EventID"] == 4625

    def test_loader_yaml_file(self):
        from adft.core.ingestion.loader import LogLoader
        loader = LogLoader()
        content = "- EventID: 4672\n  User: admin\n"
        path = _write(content, ".yaml")
        events = loader.load(path)
        assert len(events) == 1
