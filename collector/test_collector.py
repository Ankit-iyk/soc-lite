"""Unit tests use fixed XML fixtures; none of these tests reads live event logs."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

import agent
from state import load_checkpoints, save_checkpoints, validate_api_url


WINDOWS_4625_XML_FIXTURE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-27T10:00:00.0000000Z" />
    <EventRecordID>8421</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WS-01</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="TargetUserName">analyst</Data>
    <Data Name="IpAddress">192.0.2.9</Data>
    <Data Name="IpPort">51422</Data>
    <Data Name="Status">0xc000006d</Data>
  </EventData>
</Event>"""


class CollectorStateTests(unittest.TestCase):
    def test_checkpoint_survives_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoints.json"
            save_checkpoints(path, {"System": 140, "Security": 8421})
            self.assertEqual(load_checkpoints(path), {"Security": 8421, "System": 140})

    def test_http_is_permitted_only_for_loopback(self):
        self.assertEqual(validate_api_url("http://localhost:3000/api/"), "http://localhost:3000/api")
        with self.assertRaises(ValueError):
            validate_api_url("http://192.0.2.10:3000/api")
        self.assertEqual(validate_api_url("https://soc.example.test/api"), "https://soc.example.test/api")


class CollectorEventTests(unittest.TestCase):
    def test_parses_windows_4625_xml_fixture_and_preserves_original(self):
        record = agent.xml_to_record(WINDOWS_4625_XML_FIXTURE, "Security")
        self.assertEqual(record["eventId"], 4625)
        self.assertEqual(record["eventRecordId"], "8421")
        self.assertEqual(record["timeCreated"], "2026-10-27T10:00:00.0000000Z")
        self.assertEqual(record["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(record["hostname"], "WS-01")
        self.assertEqual(record["userSid"], "S-1-5-18")
        self.assertEqual(record["details"]["TargetUserName"], "analyst")
        self.assertEqual(record["details"]["IpAddress"], "192.0.2.9")

        with patch.object(agent.win32evtlog, "EvtRender", return_value=WINDOWS_4625_XML_FIXTURE):
            rendered = agent.event_to_record(object(), "Security")
        self.assertEqual(rendered["content"], WINDOWS_4625_XML_FIXTURE)


class CollectorDeliveryTests(unittest.TestCase):
    def test_splits_batches_below_request_size_and_rejects_an_oversized_event(self):
        records = [{"content": "a" * 40}, {"content": "b" * 40}]
        batches = agent.split_batches(records, maximum_bytes=100)
        self.assertEqual([len(batch) for batch in batches], [1, 1])
        self.assertTrue(all(
            len(agent.json.dumps({"logs": batch}, ensure_ascii=False).encode("utf-8")) <= 100
            for batch in batches
        ))
        with self.assertRaises(ValueError):
            agent.split_batches([{"content": "x" * 200}], maximum_bytes=100)

    def test_acknowledgement_must_be_valid_before_checkpoint_advances(self):
        valid = {"success": True, "data": {"ingested": 1, "skipped": 1}}
        agent.validate_ingest_acknowledgement(valid, 2)

        invalid_responses = (
            None,
            {"success": False, "data": {"ingested": 2, "skipped": 0}},
            {"success": True, "data": {"ingested": 1}},
            {"success": True, "data": {"ingested": 0, "skipped": 1}},
        )
        for response in invalid_responses:
            with self.assertRaises(agent.PermanentRequestError):
                agent.validate_ingest_acknowledgement(response, 2)

    def test_retries_temporary_backend_failure_without_exposing_token(self):
        response = MagicMock(status_code=200, ok=True)
        response.json.return_value = {"success": True}
        session = MagicMock()
        session.post.side_effect = [requests.Timeout(), response]

        class NoDelayStop:
            @staticmethod
            def is_set():
                return False

            @staticmethod
            def wait(_seconds):
                return False

        output = io.StringIO()
        with patch.object(agent, "stop_event", NoDelayStop()), redirect_stdout(output):
            result = agent.post_json(session, "http://127.0.0.1:3000/api", "secret-token", "checkin", {})

        self.assertEqual(result, {"success": True})
        self.assertEqual(session.post.call_count, 2)
        self.assertNotIn("secret-token", output.getvalue())

    def test_does_not_retry_invalid_agent_credentials(self):
        response = MagicMock(status_code=401, ok=False)
        session = MagicMock()
        session.post.return_value = response

        with self.assertRaises(agent.PermanentRequestError):
            agent.post_json(session, "http://127.0.0.1:3000/api", "secret-token", "checkin", {})
        self.assertEqual(session.post.call_count, 1)

    def test_retry_is_bounded_when_backend_stays_unavailable(self):
        session = MagicMock()
        session.post.side_effect = requests.ConnectionError("backend unavailable")

        class NoDelayStop:
            @staticmethod
            def is_set():
                return False

            @staticmethod
            def wait(_seconds):
                return False

        with patch.object(agent, "stop_event", NoDelayStop()), self.assertRaises(requests.RequestException):
            agent.post_json(
                session,
                "http://127.0.0.1:3000/api",
                "secret-token",
                "ingest",
                {"logs": []},
                maximum_attempts=3,
            )

        self.assertEqual(session.post.call_count, 3)


if __name__ == "__main__":
    unittest.main()