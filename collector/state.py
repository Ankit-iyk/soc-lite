"""Portable state and endpoint helpers for the Windows Event Log collector."""

import json
import os
from pathlib import Path
from urllib.parse import urlparse


def validate_api_url(api_url):
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("api_url must be an absolute HTTP(S) URL")
    is_loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError("HTTPS is required unless api_url points to localhost")
    return api_url.rstrip("/")


def load_checkpoints(path):
    checkpoint_path = Path(path)
    if not checkpoint_path.exists():
        return {}
    with checkpoint_path.open("r", encoding="utf-8") as state_file:
        state = json.load(state_file)
    if not isinstance(state, dict) or any(
        not isinstance(channel, str) or not isinstance(record_id, int) or record_id < 0
        for channel, record_id in state.items()
    ):
        raise ValueError("checkpoint file has an invalid format")
    return state


def save_checkpoints(path, checkpoints):
    checkpoint_path = Path(path)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8") as state_file:
        json.dump(checkpoints, state_file, sort_keys=True)
        state_file.flush()
        os.fsync(state_file.fileno())
    os.replace(temporary_path, checkpoint_path)