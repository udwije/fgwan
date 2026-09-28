# Running fgwan as a Windows service

No console window, starts at boot, survives logoff and restarts on failure.

## Install

From an **elevated** PowerShell:

```powershell
& "$env:ProgramFiles\fgwan\Manage-Fgwan.ps1" -Action Install
```

That registers a real Windows service:

| Property | Value |
|---|---|
| Name | `fgwan` |
| Display name | fgwan - FortiGate WAN Monitor |
| Account | `NT AUTHORITY\LocalService` |
| Startup | Automatic (delayed) |
| Recovery | restart after 60 s, 3 attempts, counter resets daily |
| Log | `%ProgramData%\fgwan\logs\fgwan.log` |

It appears in `services.msc` and answers to `sc.exe`, `Start-Service`, `Stop-Service` and
`Restart-Service` like any other service.

**Delayed start is deliberate.** Routing and the network stack are frequently not ready at the
instant services first run, and an immediate SNMP timeout is a noisy way to begin.

If you previously used the scheduled task, `Install` **detects and removes it** first. Leaving
both would mean two collectors fighting over port 8080.

## Day-to-day

```powershell
$m = "$env:ProgramFiles\fgwan\Manage-Fgwan.ps1"

& $m -Action Status          # service state + live /healthz payload
& $m -Action Logs -Tail 50   # tail the log file (follows, like tail -f)
& $m -Action Restart
& $m -Action Configure       # opens the reconfiguration wizard
```

`Status` shows the service state *and* the health endpoint, because those answer different
questions. A service showing **Running** while `/healthz` reports climbing `snmp_timeouts`
means the process is fine and the SNMP path is not.

**Changing monitored interfaces still needs none of this.** Open the dashboard, click
**configure**, save with *apply immediately*. The service reconfigures in place.

## Logging

A service has no console, so `-service` sends the log to a file. It rotates at 8 MB and keeps 3
previous files, so a host nobody looks at cannot fill its disk:

```
fgwan.log  fgwan.log.1  fgwan.log.2  fgwan.log.3
```

Tune with `-log-max-mb` and `-log-keep`. In the foreground, `-log <path>` writes to **both** the
console and the file.

## If the service will not start

Check the log first — `Manage-Fgwan.ps1 -Action Logs`. Startup failures are written there
before the process exits.

| Symptom | Cause |
|---|---|
| Starts, then stops immediately | Usually a missing or unreadable config. The log names the path it tried. |
| `cannot listen on 127.0.0.1:8080` | Something else holds the port: `netstat -ano \| findstr :8080` |
| Config saves revert after restart | LOCAL SERVICE cannot write `config.json` — re-run `-Action Install`, which grants it |
| Stops after 3 restarts | Recovery gave up on a persistent fault. Fix what the log reports, then `-Action Start`. |
| Error 1053 (did not respond in time) | The binary was registered without `-service` on its command line — re-run `-Action Install` |

A broken configuration makes the service exit rather than sit there polling nothing. That is
intentional: recovery retries three times, then leaves it stopped so the failure is visible
instead of silently looping.

## Running in the foreground still works

Nothing was taken away. Without `-service` it behaves exactly as before, logging to the console
— which remains the quickest way to try something:

```powershell
.\fgwan.exe -sim
```

If `-service` is passed but the process was *not* launched by the SCM, it says so and runs in
the foreground rather than failing with an opaque error.

## Implementation note

The SCM integration is written directly against `advapi32` — `StartServiceCtrlDispatcherW`,
`RegisterServiceCtrlHandlerExW`, `SetServiceStatus` — in the same spirit as the DPAPI
credential store. That keeps the zero-dependency property intact, so `go build` still works on
an air-gapped host with no module proxy.

The alternative was `golang.org/x/sys/windows/svc`, which would have been the project's first
external dependency for about 150 lines of well-documented, stable API surface.
