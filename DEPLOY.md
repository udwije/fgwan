# Deploying fgwan to a server without dev tools

Build on one machine, run on another. The target server needs **no Go, no WiX, no .NET SDK,
no browser and no installer framework** — only PowerShell and `sc.exe`, both part of Windows.

`fgwan.exe` is built with `CGO_ENABLED=0` and embeds its own UI, so there is no runtime to
install and no DLLs to carry.

---

## The one thing that is not portable

**`credentials.dat` cannot be copied between machines.**

It is encrypted with DPAPI in **machine scope**, so the key is bound to the machine that wrote
it. A blob carried from the build host or another server fails here with:

```
secret: CryptUnprotectData failed (blob written on another machine, or tampered with)
```

That is the protection working, not a defect — it is the same property that stops someone
lifting the file off a backup. The passphrases are entered **once on the target**, and
`Deploy-Fgwan.ps1` prompts for them.

Everything else travels fine:

| File | Portable? | Why |
|---|---|---|
| `fgwan.exe` | Yes | Static, self-contained |
| `config.json` | Yes | Holds no secrets — device address, non-secret SNMPv3 parameters, zone layout |
| `credentials.dat` | **No** | Machine-scoped DPAPI |

---

## On the build machine

```powershell
.\deploy\Package-Fgwan.ps1 -Version 1.6.0
```

Produces `dist\fgwan-1.6.0-amd64-deploy.zip` — about 6 MB, containing the binary, the deploy
and management scripts, and the docs. Note the printed SHA256 so you can verify it after the
copy.

For a **new monitor** that is nothing to do with the build host, this is all you need: the
target does its own walk and picks its own interfaces. `-IncludeConfig` exists only for the
narrower case of cloning an identical monitor onto a second server.

---

## On the target server

Copy the zip across, then in an **elevated** PowerShell:

```powershell
Expand-Archive .\fgwan-1.6.0-amd64-deploy.zip -DestinationPath C:\fgwan-deploy
cd C:\fgwan-deploy
powershell -ExecutionPolicy Bypass -File .\Deploy-Fgwan.ps1
```

### Why `-ExecutionPolicy Bypass`

Most servers ship with `RemoteSigned`, and files that arrived over a share or inside a zip
carry a **Mark of the Web** — PowerShell then refuses to run the script. The `Bypass` above
handles the first run, and the script calls `Unblock-File` on everything in the folder so
subsequent runs work normally.

If your policy forbids `Bypass`, unblock first and run it directly:

```powershell
Get-ChildItem C:\fgwan-deploy | Unblock-File
.\Deploy-Fgwan.ps1
```

### What the script does

1. **Pre-flight** — elevation, 64-bit, files present, Mark of the Web cleared, binary actually
   runs here.
2. **Installs files** to `C:\Program Files\fgwan`.
3. **Setup** — runs the terminal wizard on this server: connects to the FortiGate, walks it,
   lets you pick interfaces and zones, and stores the passphrases encrypted for this machine.
4. **Registers the service** — LOCAL SERVICE, automatic (delayed) start, restart on failure.
5. **Firewall**, only with `-OpenFirewall`.
6. **Verifies** — confirms the service is Running *and* that `/healthz` answers, because a
   service that is up but cannot reach the firewall is the failure that actually matters.

### Setup runs in the terminal, not a browser

The graphical wizard needs a browser **on the server itself** — its endpoints only answer to
loopback, because they accept SNMPv3 passphrases in a plain HTTP body. Server Core has no
browser at all, and Desktop Experience installs ship with IE Enhanced Security Configuration
blocking even localhost.

So the default is a terminal wizard that needs nothing but the console you are already in:

```
     #    NAME                 TYPE       STATE  SPEED    NOTE
     ---------------------------------------------------------------------
     1  * port1                ethernet   up     1G       ILL-PRIMARY
     2  * port2                ethernet   up     500M     ILL-SECONDARY
     3    port9                ethernet   down   1G       operationally down
     4  * VPN-ACPL             ipsec      up     -        ipsec phase-2

     * = suggested    + = already assigned

  Name for zone 1 [WAN]: Internet Uplinks
     Select by number: ranges and lists are fine, e.g.  1-3,7,9
     Enter 'suggested' to take everything marked *, or blank to skip.
  Interfaces: 1,2
```

Zones are built one at a time, so you can put anything in any zone and mix physical interfaces
with tunnels. Tunnels prompt for a declared capacity, because SNMP does not report one.

If this server does have a usable browser and you prefer the graphical wizard:

```powershell
.\Deploy-Fgwan.ps1 -SetupMode Browser
```

Either way, once the service is running you can reconfigure from the dashboard's **configure**
button from any machine that can reach it — the restriction above applies only to the
passphrase-handling setup endpoints.

### Options

```powershell
# Dashboard reachable from the management network
.\Deploy-Fgwan.ps1 -Listen 0.0.0.0:8080 -OpenFirewall

# Graphical wizard instead of the terminal one (needs a browser on the server)
.\Deploy-Fgwan.ps1 -SetupMode Browser

# Roll out a new build to a working install: replaces the binary, keeps
# configuration and credentials, restarts
.\Deploy-Fgwan.ps1 -Upgrade
```

---

## Before you start: the FortiGate

The target server has a **different IP from your build machine**, so SNMP will time out until
the firewall is told about it. This is the most common reason a first deployment looks broken.

```
config system snmp user
    edit "fgt-monitor"
        set trusted-host <target-server-ip>/32
    next
end
```

Confirm the server can reach UDP/161 on the FortiGate, and that SNMP is enabled on the
interface it will arrive through.

Also set `set alias` on each interface you plan to monitor — the dashboard leads with the
alias, so this is what turns `port10` into a circuit name on screen.

---

## After deployment

```powershell
$m = "$env:ProgramFiles\fgwan\Manage-Fgwan.ps1"

& $m -Action Status          # service state + live /healthz
& $m -Action Logs -Tail 50   # follow the log
& $m -Action Restart
```

The service starts automatically at boot, with no console window and nobody logged in.

**Changing which interfaces are monitored needs none of this.** Open the dashboard, click
**configure**, save with *apply immediately* — the running service reconfigures in place and
keeps the history of interfaces you did not touch.

---

## Upgrading later

```powershell
# build machine
.\deploy\Package-Fgwan.ps1 -Version 1.7.0

# target, elevated
Expand-Archive .\fgwan-1.7.0-amd64-deploy.zip -DestinationPath C:\fgwan-deploy -Force
cd C:\fgwan-deploy
powershell -ExecutionPolicy Bypass -File .\Deploy-Fgwan.ps1 -Upgrade
```

`-Upgrade` stops the service, replaces the binary and restarts. Configuration and credentials
are left alone, so there is nothing to re-enter.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `running scripts is disabled on this system` | Execution policy plus Mark of the Web — use the `-ExecutionPolicy Bypass` form above |
| `CryptUnprotectData failed` | A `credentials.dat` was copied from another machine. Delete it and re-run `fgwan.exe -set-credentials` on this server |
| SmartScreen warns about the binary | Unsigned executable. Sign it, or confirm the SHA256 the packaging step printed |
| Service Running, `/healthz` shows `last_error` timeouts | The FortiGate `trusted-host` list does not include this server's IP, or UDP/161 is blocked |
| `snmp_auth_fails` climbing | Passphrase or auth protocol does not match the FortiGate user. Re-run `fgwan.exe -set-credentials` |
| `cannot listen on ...:8080` | Another process holds the port: `netstat -ano \| findstr :8080` |
| Dashboard unreachable from another machine | Default listen is loopback. Redeploy with `-Listen 0.0.0.0:8080 -OpenFirewall` |
| Config saves revert after a restart | LOCAL SERVICE cannot write `config.json` — re-run the deploy script, which grants it |
| Browser wizard unreachable from your workstation | By design: the setup endpoints are loopback-only. Use the terminal wizard instead |
| Service stops after three restarts | Recovery gave up on a persistent fault. `-Action Logs` will say what it was |

---

## Security notes for a shared server

- The dashboard has **no authentication of its own**. On loopback that is fine; exposed, put a
  TLS-terminating, authenticating reverse proxy in front.
- The reconfiguration wizard is **refused for non-loopback clients** by default, because it
  accepts passphrases in a plain HTTP body. Remote users get the dashboard, not the wizard.
- The service runs as **LOCAL SERVICE**, which is unprivileged: one outbound UDP/161 flow and
  one unprivileged local TCP listener is all it needs.
- `credentials.dat` is ACL'd to SYSTEM, Administrators and LOCAL SERVICE. Machine-scope DPAPI
  stops it being useful elsewhere, but it is **not** protection against a local administrator
  on this box.
