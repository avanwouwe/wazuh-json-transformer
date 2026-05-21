# wazuh-json-transformer
Generic Wazuh wodle that transforms any structured JSON log file into Wazuh-friendly events, injected directly into the Wazuh agent pipeline.

Includes a ready-made configuration for [Jamf Protect](https://www.jamf.com/products/jamf-protect/).

## What for?
Jamf Protect writes security events to `/var/log/JamfProtect.log` as deeply nested JSON. Wazuh's native JSON decoder maps every nested field to a root-level field, creating hundreds of garbage fields in the OpenSearch database and making rule writing impractical.

`wazuh-json-transformer` solves this by:
* tailing the log file continuously as a long-running process
* remapping a configurable set of fields to a clean `data.<namespace>.*` structure
* preserving the full original event as a string for forensic purposes
* injecting the transformed event directly into the Wazuh agent socket

## Architecture

```
Jamf Protect
  → /var/log/JamfProtect.log
      → wazuh-json-transformer (long-running wodle)
          → /Library/Ossec/queue/sockets/queue  (Wazuh agent socket)
              → Wazuh agent
                  → Wazuh manager (decoder + rules)
                      → OpenSearch
```

The process is started and supervised by Wazuh via a `<wodle name="command">` entry in `ossec.conf`. If the process crashes, Wazuh restarts it within `<interval>` seconds. On restart, the process seeks to the end of the current log file to avoid duplicate events, accepting a small gap window equal to the restart interval.

File rotation is detected by inode change. On rotation the new file is read from the beginning.

## Advantages
* no complex Wazuh configuration required beyond a single wodle entry
* works with any JSON-per-line log file, not just Jamf Protect
* real-time: events are injected into the Wazuh pipeline within at most `frequency` seconds
* self-contained compiled binary: no Python runtime required on the endpoint
* errors and crashes are reported as structured events into Wazuh itself

## Limitations
* one wodle instance per log file
* on crash or restart, events written during the restart window are missed (see Architecture above)
* tested on macOS with Jamf Protect

## Configuration

The behaviour of the transformer is driven by `config.json`. See for example the configuration of the Jamf Protect mapping:

```json
{
  "input": {
    "path": "/var/log/JamfProtect.log",
    "frequency": 1
  },
  "output": {
    "tag": "jamf"
  },
  "fields": {
    "id":               "input.match.event.timestamp",
    "timestamp":        "<now>",
    "jamf.error":       "<error>",
    "jamf.type":        "input.match.facts[0].name",
    "jamf.description": "input.match.facts[0].human",
    "jamf.severity":    "input.match.facts[0].severity",
    "jamf.pid":         "input.match.event.pid",
    "jamf.event":       "<full_source>"
  }
}
```

### `input`
| Field | Description | Default |
|-------|-------------|---------|
| `path` | Path to the log file to tail | required |
| `frequency` | Polling interval in seconds | `1` |

### `output`
| Field | Description |
|-------|-------------|
| `tag` | Wazuh tag used to identify events from this wodle. Must match the `<tag>` in `ossec.conf` |

### `fields`
Each entry maps an output field (dot-notation) to a source field (dot-notation with optional array indexing).

**Reserved source tokens:**

| Token | Description |
|-------|-------------|
| `<now>` | UTC ingestion timestamp in ISO 8601 format |
| `<full_source>` | The original raw JSON line as a string |
| `<error>` | Error message. `null` in normal operation (field is omitted). Populated on crash or parse error |
| `<source>` | Name of the transformer binary |

Source fields support dot-notation and array indexing:
```
input.match.facts[0].name  →  obj["input"]["match"]["facts"][0]["name"]
```

Missing fields are silently skipped.

### Output event example
```json
{
  "id": "1765017596.430925",
  "timestamp": "2026-05-21T09:05:50.648Z",
  "jamf": {
    "type": "CatPipedToNC",
    "description": "Reverse shell creation attempted",
    "severity": 3,
    "pid": 98392,
    "event": "{\"caid\":\"...\", ... }"
  }
}
```

## Installation

An example of how to install, based on the installation of the Jamf Protect integration.

### 1. Deploy the binary via Jamf
If you distribute the pkg via Jamf, this prevents issues with notarization.
* download the latest `.pkg` from the [releases page](https://github.com/avanwouwe/wazuh-json-transformer/releases/latest)
* upload the package to Jamf Pro
* deploy to your target endpoints via a Jamf policy
* the binary is installed to `/usr/local/bin/wazuh-json-transformer`

### 2. Deploy the wodle configuration
Create `/Library/Ossec/wodles/jamf/config.json` on each endpoint. Use the Jamf Protect configuration from the previous section as a starting point.

### 3. Add the wodle to `ossec.conf`
On each endpoint, add the following to `/Library/Ossec/etc/ossec.conf`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>jamf</tag>
  <command>/usr/local/bin/wazuh-json-transformer --config /Library/Ossec/wodles/jamf/config.json</command>
  <interval>30s</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

Then restart the Wazuh agent:
```bash
/Library/Ossec/bin/wazuh-control restart
```

### 4. Add decoder and rules to the Wazuh manager
On the Wazuh manager, add the provided [0655-jamf_rules.xml](/rules/0655-jamf_rules.xml), using the `Server Management` > `Status` menu.

Then restart the manager, for example using the `Restart cluster` button in the `Server Management` > `Status` menu

### 5. Turn on local logging in Jamf Protect
* Connect to the Jamf Protect console (yourname.protect.jamfcloud.com)
* Create an `Action` called `local logging`
* Add a `Data Endpoint` of type `LogFile` to the `Action`
  * `Path` : `/var/log/JamfProtect.log`
  * `Ownership` : `root:wheel`
  * `Permissions` : `0640`
  * `Max file size` : `100` (Mb)
  * `Max number of backups` : `10`
* If you have modified the default setup of Jamf Protect and you use `Jamf Protect Cloud` using data forwarding, be sure to copy the values from the default Action, so that the events stay also visible there. The default values are:
  * Check `High`, `Medium` and `Low`
  * Uncheck `Telemetry` and `Unified logs`
* Edit the default `Plan`
  * Set `Actions` to the new action you just defined

## Frequently Asked Questions

### What if I want to monitor a different JSON log file?
Create a separate wodle directory and config:
```
/Library/Ossec/wodles/myapp/config.json
```
Add a separate wodle entry to `ossec.conf` pointing to the new config:
```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>myapp</tag>
  <command>/usr/local/bin/wazuh-json-transformer --config /Library/Ossec/wodles/myapp/config.json</command>
  <interval>30s</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
The single binary handles any number of log files simultaneously, each with its own config and wodle entry.

### How do I know if the transformer is running?
```bash
ps aux | grep wazuh-json-transformer
```
You can run the command manually to test that the events are being correctly transformed. Errors can be injected into Wazuh as structured events, allowing you to write a Wazuh rule to alert on transformer errors directly in the dashboard.