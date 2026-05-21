#!/usr/bin/env python3
"""
wazuh-json-transformer
======================
Generic JSON log transformer for Wazuh.
Transforms any JSON log file into Wazuh-friendly JSON output.
Designed to run as a long-running Wazuh Wodle (timeout=0).
Writes events directly to the Wazuh agent socket.

  <wodle name="command">
    <disabled>no</disabled>
    <tag>jamf</tag>
    <command>/usr/local/bin/wazuh-json-transformer --config /Library/Ossec/wodles/jamf/config.json</command>
    <interval>30s</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>

Usage:
    wazuh-json-transformer --config <path>
"""

import argparse
import json
import os
import re
import signal
import socket
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Program identity - resolved once at startup, used in logs and events
# ---------------------------------------------------------------------------

PROGRAM_NAME      = os.path.basename(sys.argv[0])
DEFAULT_FREQUENCY = 1  # seconds - used if not specified in config


# ---------------------------------------------------------------------------
# Logging state
# Initialized in main() after config is loaded.
# log_error() sends to Wazuh only once these are set.
# ---------------------------------------------------------------------------

_tag         = None
_socket_path = None
_config      = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso8601():
    """Current UTC time as ISO 8601 with millisecond precision."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def get_wazuh_socket_path():
    """
    Resolve the Wazuh agent socket path based on the current OS.
    macOS : /Library/Ossec/queue/sockets/queue
    Linux : /var/ossec/queue/sockets/queue
    """
    if sys.platform == "darwin":
        return "/Library/Ossec/queue/sockets/queue"
    elif sys.platform.startswith("linux"):
        return "/var/ossec/queue/sockets/queue"
    else:
        log_debug(f"Unsupported platform: {sys.platform}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log_debug(message):
    """
    Operational diagnostics - stderr only, never enters the Wazuh pipeline.
    Used for: startup, rotation, file events, SIGTERM (clean shutdown by Wazuh).
    """
    print(f"[{PROGRAM_NAME}] {message}", file=sys.stderr, flush=True)


def log_error(message):
    """
    Real errors - stderr always, Wazuh socket when available.
    Wazuh socket is unavailable during early startup (config errors),
    in which case stderr is the only output.

    Used for: JSON parse error, invalid config, config not found,
              socket write failure, SIGINT, unexpected crash.
    """
    print(f"[{PROGRAM_NAME}] ERROR: {message}", file=sys.stderr, flush=True)
    if _tag and _socket_path and _config:
        result = transform_event(None, _config, error=message)
        if result:
            send_to_wazuh(json.dumps(result), _tag, _socket_path)


# ---------------------------------------------------------------------------
# Wazuh socket communication
# ---------------------------------------------------------------------------

def send_to_wazuh(message, tag, socket_path):
    """
    Write a single event directly to the Wazuh agent socket/pipe.

    Protocol: 1:<tag>:<message>\0
    The null terminator is required by the Wazuh agent socket protocol.
    """
    payload = f"1:{tag}:{message}\0".encode("utf-8")
    try:
        if sys.platform == "win32":
            _send_to_wazuh_windows(payload, socket_path)
        else:
            _send_to_wazuh_unix(payload, socket_path)
    except Exception as e:
        # Cannot call log_error here - would recurse.
        # Build error event via transform_event and emit to stdout: read by wodle on process exit.
        error_message = f"Socket write failed: {e}"
        print(f"[{PROGRAM_NAME}] ERROR: {error_message}", file=sys.stderr, flush=True)
        result = transform_event(None, _config, error=error_message)
        if result:
            print(json.dumps(result), flush=True)
        sys.exit(1)


def _send_to_wazuh_unix(payload, socket_path):
    """Send payload via Unix domain socket (Linux/macOS)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, socket_path)
    finally:
        sock.close()


def _send_to_wazuh_windows(payload, socket_path):
    """Send payload via named pipe (Windows)."""
    with open(socket_path, "wb") as pipe:
        pipe.write(payload)


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def setup_signal_handlers():
    """
    Handle SIGTERM and SIGINT for clean shutdown logging.
    SIGTERM: expected, Wazuh shutting down the process cleanly -> log_debug.
    SIGINT:  unexpected in production -> log_error -> sent to Wazuh.
    SIGKILL: cannot be caught, no logging possible.
    """
    def handle_signal(signum, frame):
        sig_name = signal.Signals(signum).name
        if signum == signal.SIGTERM:
            log_debug(f"Received {sig_name}, shutting down")
        else:
            log_error(f"Received {sig_name}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------

def setup_exception_handler():
    """
    Catch unexpected exceptions and emit a crash event via log_error,
    which sends to both stderr and Wazuh socket.

    stdout fallback ensures the crash event reaches Wazuh even if the
    socket itself caused the crash; read by wodle on process exit.
    Double delivery in that edge case is acceptable.
    """
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, SystemExit):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        if issubclass(exc_type, KeyboardInterrupt):
            log_error("Interrupted")
            return

        message = f"{exc_type.__name__}: {exc_value}"
        log_error(f"Unexpected crash: {message}")

        # stdout fallback: read by wodle on process exit
        if _tag and _socket_path and _config:
            result = transform_event(None, _config, error=message)
            if result:
                print(json.dumps(result), flush=True)

        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = handle_exception


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# JSON path resolution
# ---------------------------------------------------------------------------

def resolve_path(obj, path):
    """
    Walk a dot-notation path with optional array indexing into a dict.

    Examples:
        "input.host.hostname"       -> obj["input"]["host"]["hostname"]
        "input.match.facts[0].name" -> obj["input"]["match"]["facts"][0]["name"]

    Returns None on any missing key, out-of-range index, or wrong type.
    """
    for part in path.split("."):
        if obj is None:
            return None
        array_match = re.match(r'^(\w+)\[(\d+)\]$', part)
        if array_match:
            key = array_match.group(1)
            idx = int(array_match.group(2))
            try:
                obj = obj[key][idx]
            except (KeyError, IndexError, TypeError):
                return None
        else:
            try:
                obj = obj[part]
            except (KeyError, TypeError):
                return None
    return obj


def set_nested(obj, path, value):
    """
    Write a value into a nested dict using dot-notation path.
    Intermediate dicts are created as needed.

    Example: set_nested(out, "jamf.type", "CatPipedToNC")
             -> out["jamf"]["type"] = "CatPipedToNC"
    """
    parts = path.split(".")
    for part in parts[:-1]:
        if part not in obj or not isinstance(obj[part], dict):
            obj[part] = {}
        obj = obj[part]
    obj[parts[-1]] = value


# ---------------------------------------------------------------------------
# Event transformation
# ---------------------------------------------------------------------------

def transform_event(raw_line, config, error=None):
    """
    Transform a raw JSON line according to config field mappings.

    When called for an error event (raw_line=None, error=<message>):
        source path resolution returns None for all fields;
        only <now>, <error>, <source> tokens produce values.

    Reserved source tokens:
        <now>         current UTC timestamp (ISO 8601, millisecond precision)
        <full_source> the original raw line preserved as a JSON string
        <error>       error message; None in normal operation (field skipped)
        <source>      executable name (PROGRAM_NAME)

    Returns a dict on success, None if the line cannot be parsed.
    """
    src = None
    if raw_line:
        try:
            src = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            log_error(f"JSON parse error: {exc} | line: {raw_line[:120]}")
            return None

    ingestion_time = now_iso8601()
    output = {}

    for dest_path, src_path in config["fields"].items():
        if src_path == "<now>":
            value = ingestion_time
        elif src_path == "<full_source>":
            value = raw_line.strip() if raw_line else None
        elif src_path == "<error>":
            value = error  # None in normal operation → field is skipped
        elif src_path == "<source>":
            value = PROGRAM_NAME
        else:
            value = resolve_path(src, src_path) if src else None

        if value is None:
            continue

        # Wazuh expects the event id field to be a string
        if dest_path == "id":
            value = str(value)

        set_nested(output, dest_path, value)

    # Ensure error events always have id and timestamp
    # even if those fields could not be resolved from the source
    if error and "id" not in output:
        output["id"] = ingestion_time
    if "timestamp" not in output:
        output["timestamp"] = ingestion_time

    return output


# ---------------------------------------------------------------------------
# File tailing
# ---------------------------------------------------------------------------

def open_and_seek_end(path):
    """Open a file, seek to EOF, return file handle."""
    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, 2)
    return f

def wait_for_file(path, frequency):
    """Block until the input file exists. Handles cold-start ordering."""
    while not os.path.exists(path):
        log_debug(f"Input file not found, retrying in {frequency}s: {path}")
        time.sleep(frequency)


def tail_file(path, config, tag, socket_path, frequency):
    """
    Core loop: tail the file, transform each JSON line, emit to Wazuh socket.

    Rotation:      detected by samefile check; new file opened from the start.
    Truncation:    detected by position > file size; seeks back to start.
    Crash/restart: on next start the process seeks to EOF (no duplicates,
                   small gap accepted as per design decision).
    """
    f = open_and_seek_end(path)
    log_debug(f"Tailing {path}")

    first_line = f.readline()
    if first_line and not first_line.endswith('\n'):
        log_debug("Discarding partial line at startup")

    while True:
        line = f.readline()

        if not line:
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                log_debug(f"File disappeared: {path}, waiting...")
                f.close()
                wait_for_file(path, frequency)
                f = open(path, "r", encoding="utf-8", errors="replace")
                log_debug(f"File reappeared, tailing {path}")
                continue

            if not os.path.samefile(f.name, path):
                log_debug(f"Rotation detected, switching to {path}")
                f.close()
                try:
                    f = open(path, "r", encoding="utf-8", errors="replace")
                except FileNotFoundError:
                    wait_for_file(path, frequency)
                    f = open(path, "r", encoding="utf-8", errors="replace")
                log_debug(f"Now tailing {path}")
                continue

            if f.tell() > stat.st_size:
                log_debug(f"Truncation detected in {path}, seeking to start")
                f.seek(0)
                continue

            time.sleep(frequency)
            continue

        line = line.strip()
        if not line:
            continue

        result = transform_event(line, config)
        if result:
            send_to_wazuh(json.dumps(result), tag, socket_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _tag, _socket_path, _config

    parser = argparse.ArgumentParser(
        description=f"{PROGRAM_NAME}: reformat JSON logs for Wazuh"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to JSON config file",
    )
    args = parser.parse_args()

    # Config errors are stderr only - logging state not yet initialized
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        log_error(f"Config file not found: {args.config}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        log_error(f"Invalid config JSON: {exc}")
        sys.exit(1)

    input_path  = config["input"]["path"]
    frequency   = config["input"].get("frequency", DEFAULT_FREQUENCY)
    tag         = config["output"]["tag"]
    socket_path = get_wazuh_socket_path()

    # Initialize logging state - log_error can now reach Wazuh
    _tag         = tag
    _socket_path = socket_path
    _config      = config

    # Signal and exception handlers registered after logging state is set
    setup_signal_handlers()
    setup_exception_handler()

    log_debug(f"Starting - config: {args.config}, input: {input_path}, "
              f"tag: {tag}, frequency: {frequency}s")

    wait_for_file(input_path, frequency)
    tail_file(input_path, config, tag, socket_path, frequency)


if __name__ == "__main__":
    main()