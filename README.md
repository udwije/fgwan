# fgwan

Real-time bandwidth monitor for FortiGate WAN members and IPsec tunnels over SNMPv3 (authPriv),
with a rolling one-hour window. Single static Go binary, embedded UI, **no external dependencies**.

- Interfaces are chosen from a live SNMP walk, not typed into a config file.
- The selection can be changed at any time **without restarting or losing history**.
- SNMPv3 passphrases live in the platform key store, never in JSON.
- Runs as a real Windows service; deploys to a server with no dev tools.

## Contents

| Document | Covers |
|---|---|
| this file | Building, running, how it works |
| `SERVICE.md` | Running as a Windows service |
| `DEPLOY.md` | Deploying to a server with no dev tools |

## Why no third-party libraries

The SNMPv3 USM layer (engine discovery, time sync, key localization, HMAC auth, AES-CFB
privacy), the WebSocket server, the DPAPI credential store and the Windows service integration
are all implemented on the Go standard library. `go build` works on an air-gapped host with no
module proxy, and the binary has no supply chain beyond the Go toolchain.

## Build

```sh
go vet ./...
go test ./...      # RFC 3414 vectors, BER encoding, rate/reset logic, zone rules, live reload
go build -o fgwan .
```

On Windows:

```powershell
.\build.ps1        # gofmt, vet, test, then build to dist\amd64\fgwan.exe
```

### Upgrade an existing installation

Download the generated deployment ZIP from the GitHub Release, extract it on the target server, and run the deployment script from an elevated PowerShell session:

```powershell
Expand-Archive .\fgwan-1.8.0-amd64-deploy.zip -DestinationPath C:\fgwan-deploy -Force
Set-Location C:\fgwan-deploy
powershell -ExecutionPolicy Bypass -File .\Deploy-Fgwan.ps1 -Upgrade
```

The upgrade replaces the application files while retaining the existing machine-local configuration and encrypted credentials. Refresh the dashboard with `Ctrl+F5` after the service restarts.

## First run

Two ways to do the initial setup. Both walk the device and write the same files.

```sh
./fgwan -setup-console     # terminal; works on Server Core, over plain RDP
./fgwan -setup             # browser wizard at http://127.0.0.1:8080/setup.html
```

The browser wizard needs a browser **on the machine running it** — the setup endpoints only
answer to loopback, because they accept passphrases in a plain HTTP body.

Then start the collector:

```sh
./fgwan
```

## Changing what is monitored

**This does not require stopping the collector.** Once fgwan is running it serves the same
wizard itself:

1. Click **configure** in the dashboard's top bar (or go to `/setup.html`).
2. Walk the device — monitoring continues while the walk runs.
3. Add, remove or re-assign interfaces and zones.
4. Save with **apply immediately** ticked.

What happens on apply:

- Credentials are **verified against the device first**. If that fails, nothing is written and
  the running collector is untouched.
- The config file is written atomically, then re-read from disk, so what gets applied is
  exactly what a restart would load.
- A new collector generation starts and the old one stops. **Interfaces you did not change keep
  their accumulated window and their counter baselines**, so their charts continue unbroken.
- If the device and credentials are unchanged, the **existing SNMP session is reused** — no
  re-handshake, no engine-ID rediscovery.
- Connected browsers are **not disconnected**; they notice the new generation and reload the
  layout themselves, including any other open tab.
- If building the new generation fails, the previous one keeps running. The failure mode is
  "nothing changed", never an outage.

The wizard shows a **diff** before you commit, and has a **revert to current** button.

On POSIX hosts, `SIGHUP` re-reads the configuration file.

### Zones are free-form

A zone is purely a **presentation grouping** — one zone becomes one chart:

- Add or remove as many zones as you want.
- Put **any** interface in **any** zone; physical interfaces and IPsec tunnels mix freely.
- Anything left unassigned is simply not monitored.
- Removing a zone returns its interfaces to unassigned rather than deleting them silently.

The only rule enforced is that **an interface belongs to exactly one zone**, so a series is
never double-counted in a zone total.

### All modes

| Command | Purpose |
|---|---|
| `fgwan` | Collector + dashboard + reconfiguration wizard |
| `fgwan -service` | Run under the Windows Service Control Manager |
| `fgwan -setup-console` | Terminal setup wizard, no browser needed |
| `fgwan -setup` | Browser setup wizard, standalone |
| `fgwan -no-setup` | Collector with reconfiguration disabled |
| `fgwan -discover` | Print the inventory, marking what is already monitored |
| `fgwan -walk OID` | `snmpwalk`-style dump of any subtree |
| `fgwan -set-credentials` | Store credentials from a console prompt (no echo) |
| `fgwan -clear-credentials` | Delete the stored credential |
| `fgwan -sim` | Full pipeline with synthetic data, no SNMP traffic |

## The dashboard

The dashboard is optimized for wall-mounted 16:9 displays, starting at 1080p, while remaining practical on a normal desktop.

- **Dark and light modes.** The selected theme is retained in the browser.
- **Capacity-aware graph scaling.** Low traffic remains readable through automatic scaling. When utilization approaches the configured limit, the chart includes the declared bandwidth ceiling.
- **Visible capacity markers.** A red dashed `CAP` line and saturation region make near-capacity traffic immediately visible.
- **Zone capacity context.** Each zone shows the combined configured capacity of its monitored interfaces.
- **Alias-first naming.** The FortiGate interface alias is emphasized while the physical port remains secondary.
- **Download and upload terminology.** Download is plotted above zero and upload below zero.
- **Compact interface summaries.** Each zone includes live download, upload, utilization, state, and capacity details.
- **Wall mode.** Typography and graph details scale for 1080p, 1440p, and 4K dashboard displays.
- **Interactive series.** Hover isolates a series, click mutes it, and smoothing changes only the rendered line, not the raw measurements.

## Credential handling

Passphrases are **never** written to the configuration file.

| Platform | Backend |
|---|---|
| Windows | DPAPI, machine scope, with application-specific entropy; blob ACL'd to SYSTEM, Administrators and LOCAL SERVICE |
| Other | AES-256-GCM with a `0600` key file (development fallback) |

Machine-scope DPAPI means the blob **cannot be copied to another machine and decrypted**, and
the entropy means another process cannot decrypt it via DPAPI with default parameters. The file
ACL keeps other local users out. It is **not** a defence against a local administrator —
nothing file-based is.

`FGT_AUTH_PASS` and `FGT_PRIV_PASS` override the key store when set.

## FortiGate configuration

```
config system snmp sysinfo
    set status enable
end
config system snmp user
    edit "fgt-monitor"
        set security-level auth-priv
        set auth-proto sha256
        set auth-pwd <auth passphrase>
        set priv-proto aes128
        set priv-pwd <priv passphrase>
        set queries enable
        set query-port 161
        set notify-hosts 0.0.0.0          # polling only, no traps
        set trusted-host <collector-ip>/32
    next
end
```

Enable SNMP on the management interface only — not on the WAN members being measured.

Set `set alias` on each interface: the dashboard leads with the alias, so this is what turns
`port10` into `ILL-PRIMARY-SLT` on screen.

## Measurement behaviour

| Concern | Handling |
|---|---|
| Physical members | `ifHCInOctets` / `ifHCOutOctets` (64-bit), `ifOperStatus`, `ifHighSpeed` |
| IPsec tunnels | Fortinet `fgVpnTunEntTable`, columns detected at setup |
| Rate | `(Δoctets × 8) / Δt`, using measured elapsed time, not the nominal interval |
| 64-bit counter going backwards | Treated as a reset — sample discarded, gap emitted |
| 32-bit counter going backwards | Corrected once for wrap |
| Implausible rate | Above `spike_guard_multiplier` × link capacity, discarded as a rekey/reset |
| Failed poll or down interface | `null` sample — the chart breaks rather than interpolating |
| Agent reboot | `sysUpTime` regression is logged and baselines rebuild naturally |
| Config change on the device | `ifIndex` re-resolved by name every `rediscover_seconds` |
| Reconfiguration | Surviving interfaces keep their window and their counter baselines |

Zone and headline totals sum only members that are currently reporting, and go to a gap only
when every member is down — a partial outage lowers the total rather than blanking it.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/interfaces` | Zones, interfaces, capacities, session parameters, config generation |
| `GET /api/series?window=3600` | Backfill of the retained window |
| `WS /ws` | One JSON frame per poll tick |
| `GET /healthz` | Poll age, SNMP timeouts, auth failures, counter resets, generation |
| `POST /api/setup/discover` | Walk the device |
| `POST /api/setup/save` | Persist the layout, and optionally apply it live |

The setup endpoints are restricted to loopback callers unless `-setup-from-anywhere` is given,
because they accept passphrases in a plain HTTP body. `-no-setup` removes them entirely.

## Security notes

- Inbound message authentication digests are **verified**, not just sent.
- DES is not implemented. AES-256 requires SHA-256 or longer, because extending a short
  localized key to 32 bytes is only described in an expired draft that agents implement
  inconsistently — better to fail loudly than to interoperate by accident.
- The server binds to `127.0.0.1` by default and has no authentication of its own. Put it
  behind a reverse proxy before exposing it — especially with the wizard mounted.
- The service runs as LOCAL SERVICE: one outbound UDP/161 flow and one unprivileged local TCP
  listener is all it needs.

## Layout

```
main.go                 flags, wiring, service/foreground modes, signal reload
setup_console.go        terminal setup wizard
reload_unix.go          SIGHUP reload (POSIX)
reload_windows.go       no-op (Windows has no SIGHUP)

internal/ber            minimal ASN.1 BER codec
internal/snmp           SNMPv3: USM crypto, message build/parse, discovery, Get/Walk
internal/discover       IF-MIB inventory and VPN table column auto-detection
internal/secret         encrypted credential store (DPAPI on Windows)
internal/term           console prompts that do not echo secrets
internal/collect        poll loop, rate engine, reset detection, simulator, broadcast hub
internal/supervise      holds the running generation; swaps it on reconfiguration
internal/store          fixed-capacity ring buffer, with history carry-over
internal/config         non-secret configuration, zone rules, atomic writes
internal/api            JSON API, WebSocket server, setup endpoints, static UI
internal/winsvc         Windows Service Control Manager integration
internal/logfile        size-rotating log writer for service mode

web/index.html          dashboard        (embedded at build time)
web/setup.html          setup wizard     (embedded at build time)

build.ps1               Windows build
installer/              service management
deploy/                 packaging and deployment to a bare server
```
