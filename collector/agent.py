"""Continuous Windows Event Log collector for SOC Lite."""

import base64
import json
import os
import platform
import signal
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pywintypes
import requests
import win32crypt
import win32evtlog

from state import load_checkpoints, save_checkpoints, validate_api_url


VERSION = "1.0.0"
MAX_BATCH_BYTES = 800_000
ALLOWED_CHANNELS = {"System", "Application", "Security"}
stop_event = __import__("threading").Event()


class PermanentRequestError(Exception):
    """An API response that needs operator action before delivery can continue."""


def load_config():
    config_path = Path(os.environ.get("SOC_LITE_COLLECTOR_CONFIG", Path(__file__).with_name("config.json")))
    with config_path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    config["api_url"] = validate_api_url(config.get("api_url", ""))
    channels = config.get("channels")
    if not isinstance(channels, list) or not channels or any(channel not in ALLOWED_CHANNELS for channel in channels):
        raise ValueError("channels must contain one or more of System, Application, Security")
    config["channels"] = list(dict.fromkeys(channels))

    interval = config.get("poll_interval_seconds", 10)
    batch_size = config.get("batch_size", 100)
    if not isinstance(interval, int) or interval < 5 or interval > 3600:
        raise ValueError("poll_interval_seconds must be an integer from 5 through 3600")
    if not isinstance(batch_size, int) or batch_size < 1 or batch_size > 200:
        raise ValueError("batch_size must be an integer from 1 through 200")
    config["poll_interval_seconds"] = interval
    config["batch_size"] = batch_size
    return config


def load_token():
    token_path = Path(os.environ.get("SOC_LITE_COLLECTOR_TOKEN_FILE", Path(__file__).with_name("token.dpapi")))
    encrypted = base64.b64decode(token_path.read_bytes(), validate=True)
    decrypted = win32crypt.CryptUnprotectData(
        encrypted,
        None,
        None,
        None,
        1,
    )
    token_bytes = decrypted[1] if isinstance(decrypted, tuple) else decrypted
    return token_bytes.decode("utf-8")


def _find(parent, name):
    return parent.find(f"{{*}}{name}")


def event_to_record(event_handle, channel):
    raw_xml = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
    record = xml_to_record(raw_xml, channel)
    record["content"] = raw_xml
    return record


def xml_to_record(raw_xml, channel):
    root = ET.fromstring(raw_xml)
    system = _find(root, "System")
    if system is None:
        raise ValueError("Windows event has no System element")

    event_id_node = _find(system, "EventID")
    record_id_node = _find(system, "EventRecordID")
    time_node = _find(system, "TimeCreated")
    provider_node = _find(system, "Provider")
    security_node = _find(system, "Security")

    details = {}
    event_data = _find(root, "EventData")
    if event_data is not None:
        for data_node in event_data.findall("{*}Data"):
            name = data_node.attrib.get("Name", "Data")
            value = data_node.text or ""
            if name in details:
                previous = details[name]
                details[name] = previous + [value] if isinstance(previous, list) else [previous, value]
            else:
                details[name] = value

    if event_id_node is None or not event_id_node.text or record_id_node is None or not record_id_node.text:
        raise ValueError("Windows event is missing its event ID or record ID")
    if time_node is None or not time_node.attrib.get("SystemTime"):
        raise ValueError("Windows event is missing its source timestamp")

    return {
        "source": channel,
        "eventId": int(event_id_node.text),
        "eventRecordId": record_id_node.text,
        "timeCreated": time_node.attrib["SystemTime"],
        "provider": provider_node.attrib.get("Name") if provider_node is not None else None,
        "hostname": _find(system, "Computer").text if _find(system, "Computer") is not None else None,
        "userSid": security_node.attrib.get("UserID") if security_node is not None else None,
        "details": details,
    }


def _close_event_handles(handles):
    for handle in handles:
        handle.Close()


def latest_record_id(channel):
    query = win32evtlog.EvtQuery(
        channel,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        "*[System]",
    )
    try:
        events = win32evtlog.EvtNext(query, 1, 0)
        if not events:
            return 0
        try:
            record = event_to_record(events[0], channel)
            return int(record["eventRecordId"])
        finally:
            _close_event_handles(events)
    except pywintypes.error as error:
        if getattr(error, "winerror", None) == 259:
            return 0
        raise
    finally:
        query.Close()


def read_new_events(channel, after_record_id, batch_size):
    query_text = f"*[System[EventRecordID > {after_record_id}]]"
    query = win32evtlog.EvtQuery(
        channel,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
        query_text,
    )
    try:
        try:
            handles = win32evtlog.EvtNext(query, batch_size, 0)
        except pywintypes.error as error:
            if getattr(error, "winerror", None) == 259:
                return []
            raise

        records = []
        try:
            for handle in handles:
                records.append(event_to_record(handle, channel))
        finally:
            _close_event_handles(handles)
        return records
    finally:
        query.Close()


def post_json(session, api_url, token, endpoint, payload, maximum_attempts=5):
    if maximum_attempts < 1:
        raise ValueError("maximum_attempts must be positive")

    delay = 1
    for attempt in range(1, maximum_attempts + 1):
        if stop_event.is_set():
            return None
        try:
            response = session.post(
                f"{api_url}/collectors/{endpoint}",
                headers={"X-Agent-Token": token},
                json=payload,
                timeout=15,
            )
            if response.status_code == 429 or response.status_code >= 500:
                raise requests.RequestException(f"retryable HTTP {response.status_code}")
            if not response.ok:
                raise PermanentRequestError(f"HTTP {response.status_code}")
            return response.json()
        except PermanentRequestError:
            raise
        except (requests.RequestException, ValueError) as error:
            if attempt >= maximum_attempts:
                raise requests.RequestException(
                    f"Backend {endpoint} failed after {maximum_attempts} attempts"
                ) from error
            print(
                f"Backend {endpoint} request failed ({type(error).__name__}); "
                f"retrying in {delay}s (attempt {attempt}/{maximum_attempts})."
            )
            stop_event.wait(delay)
            delay = min(delay * 2, 60)
    return None


def split_batches(records, maximum_bytes=MAX_BATCH_BYTES):
    batches = []
    current = []
    for record in records:
        candidate = current + [record]
        payload_size = len(json.dumps({"logs": candidate}, ensure_ascii=False).encode("utf-8"))
        if payload_size > maximum_bytes:
            if not current:
                raise ValueError("a single event exceeds the collector batch byte limit")
            batches.append(current)
            current = [record]
            if len(json.dumps({"logs": current}, ensure_ascii=False).encode("utf-8")) > maximum_bytes:
                raise ValueError("a single event exceeds the collector batch byte limit")
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def validate_ingest_acknowledgement(result, batch_size):
    if not isinstance(result, dict) or result.get("success") is not True:
        raise PermanentRequestError("server did not acknowledge the event batch")

    data = result.get("data")
    if not isinstance(data, dict):
        raise PermanentRequestError("server acknowledgment omitted data")

    ingested = data.get("ingested")
    skipped = data.get("skipped")
    if not isinstance(ingested, int) or not isinstance(skipped, int):
        raise PermanentRequestError("server acknowledgment contained invalid counts")
    if ingested < 0 or skipped < 0 or ingested + skipped != batch_size:
        raise PermanentRequestError("server acknowledgment count did not match the batch")


def report_error(session, config, token, code):
    try:
        post_json(session, config["api_url"], token, "checkin/error", {"code": code})
    except PermanentRequestError as error:
        print(f"Collector error status was rejected ({error}).")


def error_code(error):
    if isinstance(error, requests.RequestException):
        return "BACKEND_UNAVAILABLE"
    if isinstance(error, PermanentRequestError):
        return "DELIVERY_REJECTED"
    if isinstance(error, pywintypes.error) and getattr(error, "winerror", None) == 5:
        return "PERMISSION_DENIED"
    return "COLLECTION_FAILED"


def run_collector(config, token):
    state_path = Path(os.environ.get("SOC_LITE_COLLECTOR_STATE", Path(__file__).with_name("checkpoints.json")))
    checkpoints = load_checkpoints(state_path)
    pending_initialization = set()
    session = requests.Session()

    for channel in config["channels"]:
        if channel not in checkpoints:
            if config.get("start_from_beginning", False):
                checkpoints[channel] = 0
            else:
                try:
                    checkpoints[channel] = latest_record_id(channel)
                except pywintypes.error:
                    checkpoints[channel] = 0
                    pending_initialization.add(channel)
    save_checkpoints(state_path, checkpoints)

    while not stop_event.is_set():
        checkin = {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "collectorVersion": VERSION,
            "channels": config["channels"],
        }
        try:
            post_json(session, config["api_url"], token, "checkin", checkin)
        except PermanentRequestError as error:
            print(f"Collector check-in was rejected ({error}); verify the token and server configuration.")
            stop_event.wait(config["poll_interval_seconds"])
            continue

        for channel in config["channels"]:
            if stop_event.is_set():
                break
            try:
                if channel in pending_initialization:
                    checkpoints[channel] = latest_record_id(channel)
                    pending_initialization.remove(channel)
                    save_checkpoints(state_path, checkpoints)
                    continue

                newest_id = latest_record_id(channel)
                if newest_id < checkpoints[channel]:
                    print(f"{channel} record IDs moved backwards; the channel may have been cleared. Re-reading retained events.")
                    checkpoints[channel] = 0
                    save_checkpoints(state_path, checkpoints)

                records = read_new_events(channel, checkpoints[channel], config["batch_size"])
                if not records:
                    continue

                for batch in split_batches(records):
                    result = post_json(
                        session,
                        config["api_url"],
                        token,
                        "ingest",
                        {"logs": batch},
                    )
                    validate_ingest_acknowledgement(result, len(batch))

                    checkpoints[channel] = max(int(record["eventRecordId"]) for record in batch)
                    save_checkpoints(state_path, checkpoints)
                    print(f"{channel}: acknowledged {len(batch)} event(s); checkpoint {checkpoints[channel]}.")
            except (pywintypes.error, OSError, ValueError, PermanentRequestError, requests.RequestException) as error:
                print(f"{channel} collection failed ({type(error).__name__}).")
                report_error(session, config, token, error_code(error))

        stop_event.wait(config["poll_interval_seconds"])


def main():
    config = load_config()
    token = load_token()
    signal.signal(signal.SIGINT, lambda _signal, _frame: stop_event.set())
    signal.signal(signal.SIGTERM, lambda _signal, _frame: stop_event.set())
    print(f"SOC Lite collector {VERSION} starting for: {', '.join(config['channels'])}")
    run_collector(config, token)
    print("SOC Lite collector stopped.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, requests.RequestException, pywintypes.error) as error:
        raise SystemExit(f"Collector startup failed ({type(error).__name__}). Check config and permissions.") from None