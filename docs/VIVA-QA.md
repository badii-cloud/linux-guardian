# Linux Guardian — questions and answers

*Everything a professor is likely to ask, with an answer you can say out loud.*

Each entry gives a **short answer** you can lead with, then the detail, and where
it helps, the **follow-up** a professor asks next. Nothing here is invented —
every file path and command below is really in the code.

---

## Contents

| # | Section | Questions |
|---|---|---|
| A | The big picture | 8 |
| B | Where the data comes from in the OS | 16 |
| C | How live results reach the web page | 12 |
| D | The assistant — English into a Linux command | 16 |
| E | Safety and security | 13 |
| F | History, anomalies and incidents | 13 |
| G | Bash technique | 12 |
| H | Python and Flask | 9 |
| I | The hard questions | 11 |

---

## A · The big picture

### A1. In one sentence, what does this project do?

**Short answer:** It watches this Linux machine, notices when something is
wrong, explains it in plain English, and can repair one approved service — but
only after a human says yes.

The four verbs in the sidebar are the whole design: **detect · analyze ·
respond · verify**.

---

### A2. Draw the architecture.

```
Firefox (127.0.0.1:5000)
        ↓  HTTP
   Flask  (app.py)
        ↓  subprocess with an argv LIST, shell=False
   Bash modules  (linux/*.sh)
        ↓  read
   Kali Linux  (/proc, /sys, systemctl, ip, df)
        ↓  one JSON object on stdout
   back up the same path
```

Separately, a background loop samples the machine every 30 seconds into SQLite,
which is what gives the project a memory.

---

### A3. Why Bash *and* Python? Why not just one?

**Short answer:** Each does the job it is actually good at.

| Layer | Job | Why that language |
|---|---|---|
| Bash | Talk to Linux | It *is* the shell. `df`, `systemctl`, `/proc` are its native world. |
| Python | Decide and validate | Real data structures, real regular expressions, real tests. |
| Flask + Jinja | Show it | Templates, routing, JSON — trivial in Python, painful in Bash. |

The rule I kept to: **Bash measures, Python decides, Flask displays.** No Python
module shells out to `ps` or `df`, and no template computes a PASS/FAIL verdict.

---

### A4. Why does every Bash script print JSON?

**Short answer:** So Python can read the output without parsing text.

Flask does `json.loads(stdout)`. If a script printed a pretty table with colours,
Python would have to scrape it with regular expressions, and every change to the
table would break the web page. JSON is a contract: the script promises a shape,
and both sides can rely on it.

That is also why the rule is **one JSON object and nothing else** — no `echo`
progress messages, no colours, no warnings. A single stray line of text makes the
whole document unparseable.

---

### A5. What happens if a Bash script crashes?

**Short answer:** It still prints valid JSON, saying it failed.

Every script installs an `ERR` trap:

```bash
{"module":"system.sh","status":"error","message":"..."}
```

and exits 1. This matters because the alternative is a web page that shows a
Python traceback. The failure contract is: *collect every value first, print once
at the very end* — so a script can never emit half a JSON document and then die.

---

### A6. What is `config/guardian.conf` for?

**Short answer:** It is the single place every threshold, target and service name
lives — 59 settings in 12 sections.

Nothing in the project hard-codes `192.168.138.2`, `apache2`, or `80 %`. Change
one line in the config and the Bash scripts, the Python modules and the web page
all follow.

**Follow-up — "how can both Bash and Python read it?"**
It is written as plain `KEY="value"` lines. Bash does `source` (which *runs* it);
Python reads it with a regular expression and **never executes it**. That
distinction is deliberate: a web process that ran its own config file would turn
every edit to that file into code executed by the server.

---

### A7. What are the phases?

| Phase | What it added |
|---|---|
| 1 | Four read-only measuring scripts |
| 2 | `diagnosis.sh` — judges them, scores out of 100 |
| 3 | `healing.sh` — repairs one allowed service |
| 4 | The daemon + systemd unit |
| 5 | Flask web interface |
| 6 | The natural-language assistant |
| 7 | SQLite history + anomaly detection |
| 8 | Incidents, root cause, remediation |
| 9 | The plain-English layer and the guided builder |

---

### A8. What is the difference between `diagnosis.sh` and the anomaly detector?

**Short answer:** They answer two different questions, and neither replaces the
other.

- `diagnosis.sh` asks **"is this bad?"** — compares against a fixed threshold.
- `guardian_anomaly.py` asks **"is this abnormal?"** — compares against this
  machine's own recent history.

The example that makes it click: **95 % disk is bad but normal** (it has been
that way for a year). **40 % CPU on a machine that normally sits at 3 % is
abnormal but harmless.** You need both.

---

## B · Where the data comes from in the OS

### B1. Where does the CPU percentage come from?

**Short answer:** `/proc/stat`, read twice one second apart.

`/proc/stat` is a virtual file the kernel generates on demand. Its first line is
a set of **counters** — how many clock ticks the CPU has spent in each state
since boot:

```
cpu  user nice system idle iowait irq softirq steal ...
```

These only ever go up, so a single reading tells you nothing about *now* — it
tells you the average since boot. So `system.sh` does this:

```bash
read -r _ user nice system idle iowait irq softirq steal _ < /proc/stat
total=$(( user + nice + system + idle + iowait + irq + softirq + steal ))
idle_all=$(( idle + iowait ))
sleep "$CPU_SAMPLE_INTERVAL"      # 1 second
# ...read again...
```

then:

```
usage% = 100 × ( 1 − Δidle / Δtotal )
```

**Follow-up — "why is `iowait` counted as idle?"**
Because during I/O wait the CPU genuinely has nothing to do — it is waiting for
the disk. Counting it as busy would report 100 % CPU on a machine that is only
waiting for a slow disk.

**Follow-up — "why `awk` for the division?"**
Bash arithmetic is integer-only: `$(( 1 / 3 ))` is `0`. `awk` does floating point,
so we get `3.5` instead of `3`.

---

### B2. Where does memory usage come from?

**Short answer:** `/proc/meminfo`, using `MemTotal` and `MemAvailable`.

```bash
mem_total_kb="$(awk '/^MemTotal:/     { print $2 }' /proc/meminfo)"
mem_avail_kb="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)"
```

**Follow-up — "why `MemAvailable` and not `MemFree`?"**
This is the important one. `MemFree` is memory doing *nothing at all*. Linux
deliberately fills spare RAM with disk cache, so `MemFree` on a healthy machine
is tiny and would make it look like you are out of memory. `MemAvailable` is the
kernel's own estimate of what a new program could actually get — including the
cache it would reclaim. It is the honest number.

---

### B3. Where does disk usage come from?

**Short answer:** `df -P -k` on the mount point named in the config.

```bash
df -P -k "$DISK_MOUNT" | awk 'NR == 2 { ... }'
```

- `-P` is **POSIX output format**. Without it, a long device name makes `df` wrap
  the row onto two lines, and `awk 'NR==2'` would read half a row.
- `-k` forces kilobyte units, so the numbers do not change meaning if someone's
  environment sets `DF_BLOCK_SIZE`.
- `NR == 2` skips the header line.

---

### B4. Where does load average come from?

**Short answer:** `/proc/loadavg` — the first three fields.

```bash
read -r load_1min load_5min load_15min _ < /proc/loadavg
```

**Follow-up — "what does a load of 2.0 mean?"**
It is the average number of processes either running or waiting to run. On a
**4-core** machine, 2.0 means the machine is about half busy. That is why the
project also reports `load_per_core` (load ÷ `nproc`) — 1.0 there means "exactly
as much work as this machine can do", and it means the same thing on any machine.

---

### B5. Where do uptime, hostname and kernel come from?

| Value | Source |
|---|---|
| Uptime in seconds | `/proc/uptime`, first field |
| Uptime in words | `uptime --pretty` |
| Hostname | `hostname` |
| Kernel release | `uname -r` |
| CPU cores | `nproc` |

---

### B6. How do you get the top processes by CPU? Why not just use `top`?

**Short answer:** I read each process's own counters from `/proc/<pid>/stat`
twice and difference them — the same thing `top` does internally.

`top` was rejected for two concrete reasons:

- `top -b -n 1` reports each process's **lifetime average** CPU, not its current
  usage, because the first iteration has nothing to compare against. A process
  that was busy an hour ago and is idle now looks busy.
- `top -b -n 2` fixes that but **truncates process names to 8 characters** —
  `firefox+`, `qtermin+` — which is useless in a dashboard column.

So `process.sh` does it directly:

```bash
for stat_file in /proc/[0-9]*/stat; do ...      # read utime + stime
read -r uptime_before _ < /proc/uptime
#   ...sleep...
read -r uptime_after  _ < /proc/uptime
```

CPU % per process = (Δticks ÷ `getconf CLK_TCK`) ÷ elapsed seconds × 100.

**Follow-up — "what is `CLK_TCK`?"**
The kernel counts CPU time in *clock ticks*, not seconds. `getconf CLK_TCK` asks
the system how many ticks are in a second (100 on this machine). Hard-coding 100
would be a guess that is wrong on other kernels.

**Follow-up — "where does memory per process come from?"**
`/proc/<pid>/statm`, the **second field** (resident pages), multiplied by
`getconf PAGESIZE` — because that file counts **pages**, not bytes. The process
name comes from `/proc/<pid>/comm`, which is why names are never truncated.

---

### B7. Where does the network information come from?

| Value | Source |
|---|---|
| Interface list and link state | `ip -o link show` |
| IP address and netmask | `ip -o -4 addr show dev <iface>` |
| MAC address, carrier | `/sys/class/net/<iface>/…` |
| Default gateway | `ip route show default` |
| DNS servers | `resolvectl status` |
| Reachability | `ping -n -q -c N -W t <target>` |

`-o` means **one line per record**. Without it `ip` prints multi-line blocks and
parsing becomes fragile.

---

### B8. Why do you ping the gateway instead of 8.8.8.8?

**Short answer:** Because this is an offline demo VM, and 8.8.8.8 would always
fail.

The target is `PING_TARGET` in the config — `192.168.138.2`, the VMware NAT
gateway. Pinging it tests what actually matters here: *is this machine on the
network at all?* Testing internet reachability on a machine with no internet
would report a failure that is not a failure.

**Follow-up — "what do the ping flags do?"**

- `-n` — no reverse DNS lookup. Without it, ping can hang for seconds waiting on
  a DNS server that may itself be the thing that is broken.
- `-q` — quiet: only the summary, which is all we parse.
- `-c N` — send exactly N packets and stop. Without it ping runs forever.
- `-W t` — wait at most t seconds for a reply.

---

### B9. How do you check whether a service is running?

**Short answer:** `systemctl show`, not `systemctl status`.

```bash
systemctl show apache2.service --property=ActiveState,SubState,UnitFileState,...
```

`systemctl show` prints **machine-readable `key=value` pairs**. `systemctl
status` prints a human-formatted block with colour, indentation, and the last few
log lines — and its layout changes between systemd versions. Parsing it would be
scraping a UI.

**Follow-up — "what is the difference between ActiveState and SubState?"**
`ActiveState` is the general answer (`active`, `inactive`, `failed`).
`SubState` is the service-type-specific detail (`running`, `dead`, `exited`).
A service can be `active (exited)` — legitimately finished — which is not the
same as `active (running)`.

---

### B10. What does `metrics.sh` read, and why is it a separate script?

**Short answer:** It reads the same kernel files but never sleeps and never
touches the network, so it costs **52 ms** instead of `diagnosis.sh`'s 3,253 ms.

| Source | What it gives |
|---|---|
| `/proc/stat` | CPU tick counters, context switches, forks |
| `/proc/loadavg` | load 1/5/15, running + total processes |
| `/proc/meminfo` | memory and swap |
| `/proc/diskstats` | sectors read/written, disk busy ms |
| `/proc/net/dev` | bytes, packets, errors per interface |
| `/proc/sys/fs/file-nr` | open file descriptors |
| `df -P` | disk used % |
| `ss` | listening sockets, established connections |
| `ps` | zombie count |
| `systemctl` | failed unit count |

It runs 60× cheaper because it is called every 30 seconds, forever. A sampler
that costs 3 seconds cannot run every 30 seconds.

---

### B11. What is the difference between a gauge and a counter?

**Short answer:** A gauge is true on its own; a counter is only meaningful when
you subtract two readings.

- **Gauge** — memory %, load, zombie count. "62 % memory" means something right
  now. You can average gauges.
- **Counter** — `cpu_idle_ticks`, `net_rx_bytes`, disk sectors. These only go up
  since boot. "1,847,392,001 bytes received" means nothing; "1.2 MB/s" does.

`metrics.sh` publishes them as **two separate JSON objects** as a warning label,
and the store refuses to average a counter or take the rate of a gauge.

**Follow-up — "what if a counter goes down?"**
That means the machine rebooted. It is reported as `counter_reset: true`, never
as a negative rate.

---

### B12. Why does a missing sensor report `null` instead of `0`?

**Short answer:** Because a fake zero would manufacture a fault that never
happened.

If a sensor is unavailable and we write `0`, then the next successful reading
looks like a jump from 0 to (say) 1.2 million — which the anomaly detector would
correctly flag as a huge spike. `null` says "I do not know", and the detector
skips it.

---

### B13. Why `export LC_ALL=C` in every script?

**Short answer:** So numbers are formatted with a dot, not a comma.

In a French or German locale, `awk` prints `3,5` instead of `3.5`. That is not
valid JSON — `"usage_percent": 3,5` breaks the parser. `LC_ALL=C` forces the
neutral C locale, so the output is identical on any machine.

---

### B14. Why is `/proc` used so heavily rather than commands?

**Short answer:** It is faster, it never changes format, and it needs no
privileges.

`/proc` is a virtual filesystem — the files do not exist on disk; the kernel
generates their contents when you read them. Reading `/proc/loadavg` is one
syscall. Running `uptime` starts a process, which loads a binary, which reads
`/proc/loadavg` and then formats it for a human that we then have to un-format.

---

### B15. What is `/sys` and how is it different from `/proc`?

**Short answer:** `/proc` is mostly about **processes and kernel state**; `/sys`
is about **devices**.

`network.sh` reads `/sys/class/net/eth0/address` for the MAC and
`/sys/class/net/eth0/operstate` for the link state, because those are properties
of a device.

---

### B16. Does anything here need root?

**Short answer:** Only starting a service, and it is granted through a sudoers
rule limited to exactly three commands.

All the measuring is unprivileged — any user can read `/proc` and run `df`.
`/etc/sudoers.d/linux-guardian` grants passwordless `start`, `restart` and
`reset-failed` on `apache2.service` **and nothing else**. There is deliberately
**no `stop` privilege at all**.

---

## C · How live results reach the web page

### C1. Walk me through what happens when I open the dashboard.

1. Firefox requests `GET /` from Flask.
2. `dashboard()` calls `module_data("diagnosis")`.
3. That looks `"diagnosis"` up in `ALLOWED_MODULES`, a dictionary written in the
   source. **An unknown name is a 404 before anything runs.**
4. `subprocess.run(["/…/linux/diagnosis.sh"], shell=False)`.
5. `diagnosis.sh` sources the config, runs the four Phase 1 modules, applies the
   thresholds, and prints one JSON object with a score out of 100.
6. Python does `json.loads(stdout)`.
7. Jinja renders the HTML and sends it to Firefox.

The whole sweep costs about 3.25 seconds, which is why it is not what the live
refresh uses.

---

### C2. How does the page update itself without me reloading?

**Short answer:** A small piece of JavaScript fetches `/api/overview` every 10
seconds and rewrites the numbers in place.

```javascript
setInterval(refresh, 10000);
```

`refresh()` does `fetch("/api/overview")`, reads the JSON, and calls a helper:

```javascript
function set(id, text) {
  var element = document.getElementById(id);
  if (element.textContent !== String(text)) {
    element.textContent = text;      // ← text only, never HTML
    element.classList.add("changed"); // ← a brief fade so a change is visible
  }
}
```

There is no page reload, no flicker, and your scroll position is kept.

---

### C3. Why does the JavaScript never build HTML?

**Short answer:** Because if it did, the PASS/WARNING/FAIL rule would exist in
two places and they would eventually disagree.

Every row on the dashboard — including the checks that are passing — is rendered
by **Jinja on the server**. JavaScript only rewrites text and toggles `hidden`.
That keeps the verdict logic in exactly one place: `diagnosis.sh`.

It has a second benefit: the page is complete and correct **with JavaScript
disabled**. The live refresh is an improvement on a working page, never the thing
that makes it work.

---

### C4. What is `/api/overview` and why one endpoint instead of several?

**Short answer:** One request instead of five, because it runs every ten seconds.

It returns the system reading, the incident summary, the store statistics and the
briefing line in a single JSON document. Five separate endpoints would mean five
HTTP requests, five SQLite connections and five JSON parses for one screen
refresh.

**Follow-up — "why does it not include the diagnosis?"**
Because the diagnosis sweep costs 3.25 seconds — a third of the refresh interval.
The dashboard renders it once on page load, and the live refresh updates only the
cheap numbers.

---

### C5. What happens if the fetch fails?

**Short answer:** Nothing is overwritten, and the clock starts ageing so the old
numbers announce themselves.

```javascript
} catch (error) {
  /* Deliberately empty. A failed poll must leave the page exactly as it was. */
}
```

Meanwhile a second timer runs once a second:

```javascript
clockText.textContent = age < 2 ? "updated just now" : "updated " + age + "s ago";
clock.classList.toggle("live", age < 20);
```

So after 30 seconds of failure the page says *"updated 30s ago"* and the dot goes
grey. **The worst outcome for a monitoring tool is showing a stale number that
looks current.** Blanking the value would be worse still — it would look like the
metric had gone to zero.

---

### C6. Why does polling stop when the tab is hidden?

```javascript
if (document.hidden) return;
```

A hidden tab is not being read by anybody. Polling it burns CPU on the very
machine this page is reporting the CPU of — the measurement would be affecting
the measurement.

---

### C7. Why are the charts redrawn less often than the numbers?

Numbers every 10 seconds, charts every 60. A line whose right-hand end twitches
every ten seconds is distracting, and an hour-long series does not visibly change
in ten seconds.

---

### C8. How are the charts drawn? Did you use a library?

**Short answer:** No library. They are inline SVG, drawn by hand in
`static/js/charts.js`.

Three reasons Chart.js was rejected:

1. It normally comes from a **CDN**, which would be blank during an offline
   demonstration.
2. The Debian package would need `apt` on a machine with no internet.
3. Vendoring 200 KB of minified JavaScript would mean shipping code I cannot
   explain line by line — which this project's rules forbid.

The chart colours come from CSS classes, so the colour discipline stays enforced
in one file.

**Follow-up — "what do the dashed line and the shaded band mean?"**
The dashed line is the metric's **baseline** (its normal value for this machine)
and the band is **one standard deviation** around it. An anomaly is then literally
visible: the line leaving the band.

---

### C9. Why is there no CSS or JavaScript from the internet?

Because the demonstration is offline. A single `<link>` to Bootstrap or Google
Fonts would leave the page unstyled in the viva. Everything is served by Flask
from the project's own `static/` directory.

---

### C10. Why is the server bound to `127.0.0.1` and not `0.0.0.0`?

**Short answer:** So the dashboard is reachable from this machine and nowhere
else.

```python
app.run(host="127.0.0.1", port=5000, debug=False)
```

`0.0.0.0` would publish it to the whole VMware network — including a page with a
button that restarts services.

`debug=False` is equally deliberate: Flask's debug mode serves an interactive
Python console on any error page, and anyone who could reach it could execute
arbitrary code as this user.

---

### C11. What is the colour rule on the interface?

**Short answer:** Green, amber and red mean **health status only** — nothing
else may use them.

Every button, border and link uses the blue accent instead. The reason: the
moment amber also means "this is a button", nobody can tell at a glance whether
the machine is in trouble. That is why the assistant's **Confirm** button is blue,
not amber — it is a control, not a verdict.

You can verify it mechanically:

```bash
grep -n 'var(--pass)\|var(--warn)\|var(--fail)' templates/*.html
```

Every hit must be a verdict.

---

### C12. Why does the sidebar use CSS grid rather than a fixed position?

With `position: fixed` plus a margin, the content area is still full-width
*underneath* the sidebar, so every wide table has to be told about the offset.
With a two-column grid, the content column genuinely **is** the remaining width,
so a table inside it knows how much room it has.

Below 980 px the sidebar becomes a horizontal strip — no hamburger menu, because
that would be a pile of JavaScript for a dashboard nobody browses on a phone.

---

## D · The assistant — English into a Linux command

### D1. I type "how full is my disk". Trace exactly what happens.

```
"how full is my disk"

1. TOKENISE       ["how", "full", "disk"]
                  punctuation → spaces, filler words dropped

2. MATCH          check_disk, confidence 0.91, via the trigger phrase "disk"

3. VALIDATE       is "check_disk" in the registry?  yes
                  does it need parameters?          no

4. BUILD          ["/…/linux/system.sh"]     ← a LIST, never a string

5. EXECUTE        subprocess.run(list, shell=False)

6. NARROW         the registry says select:"disk", so take only that key

7. RENDER         a gauge, a fact table, and the raw JSON one click away
```

The important step is 3. **The text never becomes a command.** It becomes an
**id**, and the id is looked up in a table a human wrote.

---

### D2. What is `linux/actions.json`?

**Short answer:** The complete list of the 14 things the assistant is allowed to
do. If it is not in that file, it cannot happen.

Each entry declares:

| Field | Meaning |
|---|---|
| `id` | The only name the outside world may use |
| `script` | A filename inside `linux/`, written by a human |
| `args` | Fixed arguments placed before any parameters |
| `danger` | `read` runs immediately; `write` needs confirmation |
| `select` | Which key of the script's JSON answers this question |
| `params` | Each with an **anchored regular expression** |

**Follow-up — "JSON has no comments, so how is it documented?"**
Any key starting with `_` is stripped by the loader. So `_readme` and `_comment`
keys carry the explanation, and the file is still valid JSON that `jq` can read.

---

### D3. How does the matcher decide which action you meant?

**Short answer:** It scores every action on **evidence**, and evidence is
*trigger words matched + parameters that action can actually use*.

Take: `create a file called notes`

| Action | Trigger words | Usable parameters | Evidence |
|---|---|---|---|
| `create_file` | "create file" = 2 | `name` = 1 | **3** |
| `list_files` | "file" = 1 | none = 0 | 1 |

`create_file` wins 3 to 1. Now take `list my files`:

| Action | Trigger words | Usable parameters | Evidence |
|---|---|---|---|
| `list_files` | "list files" = 2 | 0 | **2** |
| `create_file` | 0 | 0 | 0 |

The rule is simple to defend: **an interpretation that accounts for more of what
you actually said is the better interpretation.** Reading "create a file called
report every Thursday at 9am" as `create_file` would throw away the day and the
time; `schedule_file` uses all three.

---

### D4. How is the confidence number calculated?

Longer trigger phrases score higher, because they are stronger evidence:

- Every word of the phrase present **and consecutive** → `0.78 + 0.06 × words`, capped at 0.97
- Every word present but scattered → `0.72 + 0.05 × words`, capped at 0.93
- Partial match (at least 2 words, at most 1 missing) → `0.55 + 0.05 × matched`

Then `+0.03` per usable parameter. The threshold to act is
`MATCH_MIN_CONFIDENCE = 0.75`, set in the config.

"create file" matching as a run is far better evidence than the single word
"file" appearing somewhere.

---

### D5. What happens when two readings are equally good?

**Short answer:** It refuses to choose and asks you.

```python
if (scored[0].evidence == scored[1].evidence
        and abs(scored[0].confidence - scored[1].confidence) < 0.05):
    scored[0].confidence = min(scored[0].confidence, min_confidence() - 0.01)
```

The winner's confidence is deliberately pushed **below the threshold**, which
makes the console show a "did you mean?" list instead of running something. It is
the same instinct as the healing allow-list: **when unsure, do nothing.**

---

### D6. What are the stopwords for?

Words like `a`, `the`, `my`, `please`, `can`, `you` carry no clue about *which*
action is wanted. Removing them lets "create **a** file" match the trigger phrase
"create file" as a contiguous run, which scores higher than two words that merely
both appear somewhere.

The list is deliberately short — every word removed is a word that can no longer
distinguish two actions.

---

### D7. How do you get the file name out of "create a file called notes"?

Regular expressions look for the ways people actually name things:

```python
r"['\"]([^'\"]{1,60})['\"]"                        # quoted
r"\b(?:called|named|name)\s+(?:(?:a|an|the|my|new)\s+)*([^\s,]{1,60})"
r"\b(?:file|note|schedule|timer)\s+(?:(?:a|an|the|my|new)\s+)*([^\s,]{1,60})"
```

**Follow-up — "what is that `(?:(?:a|an|the|my|new)\s+)*` group for?"**
It skips filler between the noun and the actual name. Without it, "schedule **a**
report every Monday" captures the word `a` — grammatically the next word, and
obviously not what the user called their file.

**Follow-up — "the pattern allows characters the validator rejects. Is that a
bug?"**
No, it is deliberate. The extractor's job is to find **what the user meant**; the
validator's job is to **refuse it if it is not allowed**. Extracting
`../etc/passwd` and then rejecting it with a clear message is far better than
silently failing to see it and reporting "name is required".

---

### D8. Does the assistant use AI?

**Short answer:** It can, optionally — but it does not need to, and AI is never
allowed to override it.

There are three attempts, in this order:

1. **The keyword dictionary.** Always available, no network. It covers **all 14
   actions unaided**.
2. **Ollama**, a local language model — consulted **only if step 1 found nothing
   at all**.
3. **Show the list.** Never guess, never execute.

Because step 2 only ever sees sentences the dictionary had no opinion on, the
model **cannot override, reorder or second-guess** a deterministic match. Adding
or removing it cannot change any behaviour that already worked.

**Ollama is not installed on this machine**, which is the tested demo state.

---

### D9. If the model is not installed, how is that not an error?

An unmatched query returns in about **1 millisecond**, because a refused
connection on loopback is instant — there is no timeout to wait out. The console
then shows the action list and says plainly which step answered.

---

### D10. What stops the model from returning `rm -rf /`?

**Short answer:** There is nowhere in the code that a string from the model
becomes part of a command.

The model is shown the list of ids and asked to return **one of them**. Its answer
goes through `validate()`, which checks the id against the registry. Anything that
is not a key in that dictionary is rejected before anything runs.

`test_ollama.py` stubs the API and proves the gate rejects `rm -rf /`, unknown
ids, wrong case, prose, truncated JSON, and a 5-second hang.

**Follow-up — "what if the model returns the right id but a wrong parameter?"**
The rule is: **the model classifies; the regular expressions extract.** Any
parameter the deterministic extractor found in the sentence *overrides* the
model's version. A model asked about Thursday can answer "Friday" with total
confidence; a regex that matched the literal word in the text cannot.

---

### D11. Show me how a write action is different.

**Short answer:** It never runs on the first request.

```
POST /console          → validate → danger == "write" → return a PREVIEW,
                                                        run nothing
POST /console/confirm  → validate AGAIN from scratch  → execute
```

The preview says in plain English what will happen:

```
Will create   /home/kali/Desktop/linux-guardian/workspace/notes.txt
Content       hello
Script        linux/workspace.sh create notes hello
```

**Follow-up — "could I skip the preview with `curl`?"**
You could send the confirm POST directly, and it would gain you nothing. That
route re-validates the action id and every parameter **from scratch** — it does
not trust the preview it came from. **The registry is the security boundary; the
preview is a usability feature.**

---

### D12. What is the guided builder?

**Short answer:** For when you do not know what to type. You pick an action, fill
labelled boxes, and watch the English sentence *and* the Linux command build
themselves:

```
You type     create a file called notes containing hello
Linux runs   linux/workspace.sh create notes hello
```

Each field shows the rule it will be judged by **before** you type — which is a
cheaper moment than being refused afterwards.

**Follow-up — "is that a way around the validator?"**
No. The card is a plain HTML form posting to **the same route** the text box uses,
with the same `console_param_<name>` convention. A value typed into a labelled box
and a value a regular expression found in a sentence arrive at `validate()` as the
same string. `test_guide.py` §7 re-runs every hostile input through the form —
traversal, `evil.sh`, `-rf`, `ssh`, `nginx`, `funday`, `25:00` — and each is
refused with an empty argv.

---

### D13. Where do the example sentences come from? Are they hard-coded?

**Short answer:** They are checked, not claimed.

Every example is fed back through the real matcher by the test suite and must
resolve to the action it is filed under, above the threshold. An example that
stops working **fails the build** instead of embarrassing me in a demonstration.

The trigger words shown on each card are read straight out of
`guardian_nlp.TRIGGERS` — the dictionary that actually does the matching — so
there is no second list to keep in step.

---

### D14. What is `/api/console/translate`?

The endpoint behind the live "as you type" line. It runs the matcher, runs the
validator, calls `build_command()`, and **hands the resulting list to nobody**.

**Follow-up — "your rule is that anything which changes something is a POST. Why
is this a GET?"**
Because the reasoning behind that rule gives the opposite answer here. The rule
exists because browsers pre-fetch GETs. This endpoint changes nothing, so
pre-fetching it is harmless — and that *is* the test for whether a GET is
appropriate.

---

### D15. How can one action reuse a Phase 1 script without modifying it?

Through the `select` field. `system.sh` still reports CPU, RAM, disk and load
exactly as it always did. `check_disk` simply declares `"select": "disk"`, so
Python takes that one key out of the answer.

`check_service` goes one step further with `filter_by`: `services.sh` reports
every monitored service, and Python picks the one entry the parameter named.

---

### D16. What is `show_logs` doing differently?

Its `script` is `null` and it is served by Python directly. Inventing a shell
script whose entire job is `tail` would add a subprocess and a JSON-escaping
problem for no benefit — Python can read a file with one `open()`, and there is no
user input involved, so there is nothing to sanitise.

---

## E · Safety and security

### E1. What is the single most important security idea in this project?

**Short answer:** A request supplies a **name**, never a command.

```python
BAD   subprocess.run(f"linux/{name}.sh", shell=True)
      # a request for  ?name=x;rm -rf ~  runs two commands

GOOD  script = ALLOWED_MODULES[name]     # KeyError → 404, nothing runs
      subprocess.run([script], shell=False)
```

Nothing anywhere in this project builds a command out of user input.

---

### E2. Why is `shell=False` so important?

**Short answer:** With no shell in the picture, there is nothing to interpret a
`;`.

When you pass a **list**, Python hands it straight to `execve()`. Each element
arrives at the program as exactly one argument, no matter what is inside it. A
space, a semicolon, a quote or a newline is just a character in an argument.

When you pass a **string** with `shell=True`, `/bin/sh` parses it first — and `;`,
`|`, `&&`, `$()` and backticks all become operators.

---

### E3. Name the five walls.

| # | Wall | Where |
|---|---|---|
| 1 | A request supplies a name, never a command | `ALLOWED_MODULES`, `ACTIONS` |
| 2 | Every parameter matched against an **anchored** pattern | `actions.json` + `validate()` |
| 3 | Commands built as **argv lists**, `shell=False` | `build_command()` |
| 4 | Paths resolved with `realpath`, must be inside the workspace | `resolve_in_workspace()` |
| 5 | Bash re-checks everything from scratch | `healing.sh`, `workspace.sh` |

**Deleting any single one still leaves the system safe.** None of them trusts the
next.

---

### E4. Why must the patterns be anchored with `^...$`?

**Short answer:** An unanchored pattern matches a *substring*.

The pattern `[a-z]+` matches inside `schedule; rm -rf /` — because the substring
`schedule` matches. Anchoring with `^...$` requires the **whole value** to match.

**Follow-up — "you use `re.fullmatch`, not `re.match`. Why both?"**
`re.match` anchors only the **start**. So `^[a-zA-Z0-9_-]{1,40}$` with `re.match`
would still accept a value with a newline and a payload after it, because `$` also
matches before a trailing newline. `fullmatch` requires the whole string.

---

### E5. Walk through why `../../etc/passwd` cannot escape the workspace.

Three independent checks, each answering a different question:

1. **Is the name the right shape?** The pattern is
   `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$` — **no dot and no slash are in that
   character class**, so `../../etc/passwd` fails immediately.
2. **Where would the filesystem really put it?** `realpath` follows every symbolic
   link and flattens every `..`.
3. **Is that real destination directly inside the workspace?**
   `resolved.is_relative_to(root)` **and** `resolved.parent == root`.

A regex reasons about the **text** of a name. `realpath` reasons about **where the
filesystem would put it**. They are different questions, and a symlink planted
inside the workspace is a case where only the second one is right.

---

### E6. Why is the first character of a filename a separate character class?

```
^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,39}$
 └── no hyphen  └── hyphen allowed
```

**Short answer:** So a name can never be `-rf` or `-f`.

A value beginning with a hyphen is not a path to most Unix commands — it is a
**flag**. A validator that allows one is handing an attacker an option instead of
a filename. The hyphen is still legal anywhere after the first character, so
`my-notes` works.

---

### E7. Why is the file extension added by the script and not the user?

So the user cannot choose to write a `.service`, a `.sh` or a `.py` file. They
supply `notes`; the script writes `notes.txt`.

---

### E8. Why does `validate()` normalise *before* it checks?

**Short answer:** Because otherwise the value that gets used is not the value that
was checked — the classic way a validator gets bypassed.

The order is:

```
normalise → length cap → regex → allow-list → path containment
```

Normalising first is what lets a human type `thursday` or `12 pm` while the
validator still only ever approves the exact spelling systemd understands (`Thu`,
`12:00`).

**Follow-up — "why cap the length before running the regex?"**
A regular expression engine given a megabyte of text is an easy way to make the
server do a lot of work for one request. A cheap `len()` first means the expensive
step only ever sees a bounded value.

---

### E9. Why does the normaliser not reject `25:00` itself?

Because judging belongs in exactly one place. `normalise_time("25:00")` returns
`"25:00"` unchanged, and the anchored pattern
`^([01][0-9]|2[0-3]):[0-5][0-9]$` refuses it. One rule to read, not a rule plus a
second opinion hidden in the parser.

Note the hour alternation is what makes 25 impossible — a lazier `[0-9]{2}` would
accept it.

---

### E10. Why is `/settings` read-only?

**Short answer:** A form would let the web process rewrite the file that defines
its own limits — including `HEALABLE_SERVICES` and `PROTECTED_SERVICES`.

The page shows all 59 settings and names the file to edit, which keeps policy
where a human with a text editor controls it.

---

### E11. Why are the healing guards duplicated between Python and Bash?

**Short answer:** Defence in depth. Neither layer trusts the other.

`heal_service` is checked by:
1. the character pattern in `actions.json`
2. the allow-list read from `guardian.conf`
3. `healing.sh` re-checking `PROTECTED_SERVICES` and `HEALABLE_SERVICES`
4. `healing.sh` re-validating the characters

Deleting any one of the four still leaves the system safe.

---

### E12. Why is healing a POST and not a GET?

A GET is supposed to be **safe to repeat**. Browsers pre-fetch them, crawlers
follow them, and "open all tabs" would trigger a service restart on every one.
Anything that changes the system must be a POST.

---

### E13. Why does the sudoers rule not include `stop`?

Because Guardian's job is to bring a service **up**, never to take one down. A
tool that can stop services is a tool that can cause the outage it is supposed to
detect. Restaging the demo therefore needs a human:
`sudo systemctl stop apache2`.

---

## F · History, anomalies and incidents

### F1. Why does the project need a database at all?

**Short answer:** Without history, nothing can say *"86 % is high **for this
machine**"*.

Phases 1–6 were amnesiac: every reading was measured, judged, shown and thrown
away. Phase 7 is sampler → store → detector, in that order.

---

### F2. Describe the database schema.

```
sample_runs      one row per tick        (ts, source, duration)
samples          one row per metric      PRIMARY KEY (metric, ts) WITHOUT ROWID
incidents        one row per condition   fingerprint = type + component
incident_events  the timeline            records CHANGES, not ticks
```

**Follow-up — "why one row per metric rather than one wide row per tick?"**
Because narrow means adding a field to `metrics.sh` needs **no schema change**,
and the statistics stay generic. `PRIMARY KEY (metric, ts) WITHOUT ROWID` also
makes "metric X over the last N seconds" one contiguous range read.

Cost: about 52 bytes per row, roughly 30 MB per week at 30 metrics every 30
seconds.

---

### F3. How does retention work?

**Short answer:** Two guards that fail differently.

1. **By age** (`HISTORY_RETENTION_HOURS = 168`) — expresses the intent, and is
   useless if the clock is wrong.
2. **By row count** (`HISTORY_MAX_ROWS = 1000000`) — never consults the clock, so
   a VM resuming from suspend believing it is 1970 still cannot fill the disk.

Whole **ticks** are deleted, never individual rows: a half-deleted moment would
read to the detector as the machine losing sensors.

---

### F4. How does the anomaly detector work?

**Short answer:** It compares a recent window against a baseline window, and
**two tests must both pass**.

1. **Statistical** — at least `ANOMALY_Z_WARNING` (3.0) standard deviations from
   the baseline.
2. **Material** — also at least `ANOMALY_MIN_CHANGE_PERCENT` (10 %) of the
   baseline.

**Follow-up — "why the second test?"**
Because a metric sitting flat at 3.00 has almost no variance, so a move to 3.05
gives a z-score around 50 — statistically enormous, practically nothing. Without
the material test the dashboard would shout about noise.

**Follow-up — "is that dampener a blindfold?"**
No, and there is a test for exactly that: the same metric jumping to 45.0 is still
reported CRITICAL.

---

### F5. How do you stop the detector teaching itself that the anomaly is normal?

**Short answer:** The baseline window **ends where the recent window begins**.

There is no overlap, so a long spike can never drag up the average it is being
judged against. A test holds the baseline at 20.00 while the recent window sits at
90.03.

---

### F6. What does LEARNING mean?

**Short answer:** "I do not know yet" — which is a different statement from
"everything is fine".

Below `ANOMALY_MIN_SAMPLES` (20) there is not enough history to judge, so the
verdict is the distinct word `LEARNING`, and it sorts **last** so it never pushes
a real finding down the page. Reporting NORMAL there would be a lie.

---

### F7. Why Chebyshev and not the normal distribution?

**Short answer:** Because CPU usage is not bell-shaped, and claiming otherwise
would be fabricated precision.

Chebyshev's inequality says P(|X − μ| ≥ kσ) ≤ 1/k² **for any distribution**. CPU
usage is bounded (0–100), skewed and bursty. A bell curve would let me report
"3σ = 99.7 % confident"; Chebyshev reports **88.9 %** — a smaller number that is
actually true.

---

### F8. Tell me about a bug a test found that reading the code did not.

**Short answer:** The zero-variance blind spot.

A counter incrementing by exactly the same amount every tick has a rate with **no
variance**. σ = 0, so there is no z-score to compute — and the first version
reported a **20× traffic spike as NORMAL**.

The fix: when σ = 0 the test becomes *"is the value outside everything the
baseline has ever seen?"*, which needs no σ. Such a finding is capped at WARNING
and reports `confidence: null` — no plausible number is invented for a spread that
does not exist.

---

### F9. Why is `stddev` calculated with Welford's algorithm?

**Short answer:** Because the textbook formula loses catastrophic precision at
counter magnitudes.

`sum(x²)/n − mean²` subtracts two huge, nearly equal numbers. At counter
magnitudes (10⁹) it is **36 % wrong**, and at 10¹⁰ it returns 0.0. Welford's
method updates the mean and variance incrementally, so nothing large is ever
subtracted from anything large.

There is a second numerical care in the trend calculation: the least-squares slope
**shifts time to start at zero before squaring**, because Unix timestamps are
about 1.8 × 10⁹ and squaring them passes 2⁵³. A test runs the same regression on
raw timestamps and gets 123.006 where the answer is exactly 120.000.

---

### F10. What is an incident, and why not just list the anomalies?

**Short answer:** Because one cause was producing four alarms.

Phase 7 ended with a single CPU load producing **four CRITICAL findings** —
`load_1min`, `load_5min`, `load_per_core` and `cpu_idle_ticks`. All four were
correct. An alert list where one cause fills four rows is one people stop reading.

An incident groups metrics that are **symptoms of the same condition**, declared
in `linux/incidents.json`. Now it is **one incident with six symptoms**.

**Follow-up — "why declare the correlation instead of learning it?"**
Statistical correlation needs weeks of labelled data this machine does not have,
and would produce groupings nobody could defend in a viva.

---

### F11. How does deduplication work?

**Short answer:** An incident's fingerprint is **type + component** — deliberately
*not* its symptom list.

A condition that starts with three symptoms and grows to six is still the same
condition. A test runs 12 consecutive scans and gets **1 row, occurrences 12, 3
timeline entries** — because the timeline records *changes*, not ticks.

---

### F12. Severity and risk are different numbers. Why?

**Short answer:** They answer different questions, and their disagreement is the
useful part.

- **Severity** — *how bad is this if it is real?*
- **Risk** — *how much should I care right now?* A weighted average over severity,
  confidence, impact, persistence, recurrence and security.

A CRITICAL finding Guardian is unsure about is a smaller problem than a HIGH one
it is certain of.

**Follow-up — "why a weighted average and not a sum of penalties?"**
Because a sum can exceed 100 and can be gamed by adding more factors. An average
cannot. It also returns `contributions`, so "risk 65" is explainable as "of which
14 is impact".

**Follow-up — "what is the confidence cap?"**
Severity is capped at MEDIUM below `SEVERITY_MIN_CONFIDENCE_FOR_HIGH`, and the cap
is applied **last** so nothing gets past it. A CRITICAL that turns out to be noise
costs more than a missed MEDIUM: it teaches people to stop reading.

---

### F13. Explain the incident state machine.

```
DETECTED → INVESTIGATING → WAITING_APPROVAL → REMEDIATING → VERIFYING → RESOLVED
                                                                     ↘ FAILED
```

**`REMEDIATING → RESOLVED` is not a legal transition.** It must pass through
`VERIFYING`. "Never trust an exit code as proof of success" is therefore enforced
by the transition table, not by a comment somebody may not read.

**Follow-up — "what happens if a fix fails?"**
The incident goes to `FAILED` and stays **open**. There is no automatic retry, and
the timeline says so.

**Follow-up — "what if the problem goes away on its own?"**
It is auto-resolved, but **only from `DETECTED` or `INVESTIGATING`**. An incident
at `WAITING_APPROVAL` has a human involved, and closing it from underneath them
would destroy the record of what was being decided. The timeline says plainly
*"returned to normal on their own; no action was taken"* — never that something
fixed it.

---

## G · Bash technique

### G1. What does `set -euo pipefail` do?

| Flag | Effect | Why it matters |
|---|---|---|
| `-e` | Exit on any command failure | A failed `df` must not be treated as "0 % used" |
| `-u` | Error on an undefined variable | A typo in a variable name fails loudly instead of expanding to empty |
| `-o pipefail` | A pipeline fails if **any** stage fails | Without it, `false \| cat` succeeds, because only the last exit code counts |

---

### G2. Why resolve paths from `${BASH_SOURCE[0]}`?

**Short answer:** Because systemd runs these scripts from `/`.

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```

A relative path like `../config/guardian.conf` depends on the **working
directory**, which is whatever the caller happened to be in. `${BASH_SOURCE[0]}`
is the path of the script itself, so the config is found whether you run it from
the project directory, from `/`, or from a systemd unit.

---

### G3. Why quote every variable?

Because without quotes, the shell splits the value on spaces and expands globs.
`rm $file` where `file="my notes.txt"` tries to delete two files. `"$file"` is one
argument, always.

---

### G4. What is the difference between `$(...)` and backticks?

`$(...)` nests cleanly and is the POSIX-recommended form. Backticks require
escaping inside nesting and are visually easy to confuse with quotes.

---

### G5. Why `read -r`?

Without `-r`, `read` treats backslashes as escape characters and mangles any value
containing one. `-r` reads the line literally.

---

### G6. Why does `healing.sh` verify instead of trusting `systemctl start`?

**Short answer:** Because a zero exit code means "the request was accepted", not
"the service is running".

`systemctl start` returns as soon as systemd accepts the job. The service can
still fail a second later. So `healing.sh` re-runs `systemctl show` up to
`HEAL_VERIFY_ATTEMPTS` times with `HEAL_VERIFY_DELAY` between, and reports what it
actually measured.

---

### G7. What makes `healing.sh` idempotent, and why does it matter?

If the service is already running it returns `result: "already_healthy"`,
`action: "none"` — it does not restart it. That matters because the daemon calls
it every 30 seconds; a non-idempotent version would restart a healthy service 2,880
times a day.

---

### G8. How does the daemon shut down cleanly?

It installs a `trap` on `SIGTERM` and uses an **interruptible sleep**, so
`systemctl stop` takes under a second rather than up to 30. A plain `sleep 30`
would ignore the signal until it finished.

---

### G9. Why does the daemon collect *before* it heals?

**Short answer:** A sample taken after an intervention would describe the machine
*after* the fix.

Order is **collect → heal**. Also, collection is *subordinate*: a missing
`healing.sh` is fatal, but a broken database logs one line and the daemon keeps
watching apache2.

**Follow-up — "why log only on transition?"**
Because a failure logged every 30 seconds is 2,880 identical lines a day — filling
the very disk whose exhaustion may have caused the failure.

---

### G10. Why are schedules systemd **user** timers and not cron?

| | cron | systemd user timer |
|---|---|---|
| Privilege | root crontab needs root | runs as this user |
| Validation | none until it fires | `systemd-analyze calendar` checks first |
| Logging | mail, if configured | `journalctl --user` |
| Status | none | `systemctl --user list-timers` |

Crucially, `systemd-analyze calendar "Thu 12:00"` validates the expression with
**systemd's own parser** before any file is written — not just with our regex.

**Follow-up — "what is the limitation?"**
User timers only run while the user has a session. `Linger=no` on this VM.
`sudo loginctl enable-linger kali` would change that; it needs root and is not
needed for the demo.

---

### G11. How do you prove a script emits real JSON numbers?

```bash
./linux/system.sh | jq '[paths(scalars) as $p | {k:($p|join(".")), t:(getpath($p)|type)}]'
```

This lists every scalar in the document with its JSON type. `"usage_percent"`
must be `number`, not `string`. `"3.5"` in quotes would force every consumer to
convert it, and a chart library would sort it as text.

---

### G12. What does `shellcheck` catch that you would miss?

Unquoted variables, useless `cat`, `[ ]` versus `[[ ]]` subtleties, unreachable
code, and subshell variable scoping. All 10 scripts pass
`shellcheck --severity=style` with **zero warnings**.

One real finding worth mentioning: `guardian-daemon.sh` needs
`# shellcheck disable=SC2317,SC2329`, not just SC2317 — shellcheck 0.11.0 split
the old "unreachable code" check into a new "function is never invoked" code, and
the trailing `exit 0` triggers it. Both codes are named so the script lints clean
on any shellcheck version.

---

## H · Python and Flask

### H1. Why does `read_config()` not just `source` the file?

**Short answer:** Because `source` **runs** the file.

A web process that executed its own config file would turn every edit to that
file into code executed by the server. The Python side only ever **matches text**:

```python
r'^\s*([A-Z_][A-Z0-9_]*)\s*=\s*"?([^"#]*)"?'
```

---

### H2. Why not use `os.path.expandvars()` for `${GUARDIAN_ROOT}`?

Because it expands **every** `$NAME` it finds, using this process's whole
environment. A web server inherits a much bigger environment than it needs, and
expanding blindly is how a value picks up something nobody intended. Only two
named substitutions are implemented, because only two are used.

---

### H3. Why do none of the `guardian_*.py` modules import Flask?

**Short answer:** So every one can be tested from a terminal with no web server
running.

That is exactly what the nine test suites do. The web layer adds routes and
templates **on top of logic that already works without it**.

---

### H4. What does `check=False` mean in `subprocess.run`?

It means a non-zero exit code is a **result to display**, not an exception to
swallow. `healing.sh` exits 1 when it refuses a request — that refusal is
information the user should see, not a crash.

---

### H5. Why is there a timeout on every subprocess call?

Because a hung script must produce an error card, never a browser tab that spins
forever. `SCRIPT_TIMEOUT_SECONDS = 60` — generous, because `diagnosis.sh` runs
four modules that each sample for a second, but bounded.

---

### H6. Parsing the JSON succeeded. Does that mean the action succeeded?

**Short answer:** No, and assuming it did was a real bug.

The Bash contract says failures **still produce valid JSON**. So parsing succeeds
on an error document too. Forwarding one into a root-cause interpreter made
Investigate look as if it had run while it had collected no evidence. The fix:

```python
if payload.get("status") != "ok":
    return {"status": "error", "message": payload.get("message") ...}
```

---

### H7. Why does the sidebar's incident count swallow its own errors?

```python
try:
    open_incidents = gi.summary()["open"]
except Exception:
    open_incidents = None
```

This is a context processor — it runs before **every single template render,
including the error page**. If the database were unreadable and this raised, every
page in the application would return 500, including the page explaining what went
wrong. A missing count is cosmetic; an unreachable error page is not.

It is one of only two deliberate broad `except` blocks in the project, and both
are commented with why.

---

### H8. What is Jinja's `Undefined` trap you hit?

**Short answer:** `Undefined is not none` evaluates to **True**.

`healing.sh` omits `verify_attempts` entirely when a service was already healthy.
A guard that only checked `is not none` let those rows through and printed a label
with an empty value beside it. All three conditions are needed:

```jinja
{% if value is defined and value is not none and value != '' %}
```

---

### H9. Why is a metric name in a URL safe?

Three reasons, in order of importance:

1. It travels as a **bound SQL parameter**, so no SQL is ever built from it.
2. The store applies an **anchored character allow-list**.
3. An unknown metric has no rows and raises.

The `seconds` parameter is **clamped**, not trusted — a request for a hundred
years of history would be a cheap way to make the server do a lot of work.

---

## I · The hard questions

### I1. Is any of this actually "self-healing"? A human has to approve.

**Short answer:** Both modes exist, and the difference is deliberate.

- The **daemon** heals `apache2` automatically, with no human — that is genuine
  self-healing, restricted to one allow-listed service.
- The **incident flow** requires approval, because it can propose actions derived
  from an analysis, and an analysis can be wrong.

The design position: automation is safe when the set of possible actions is fixed
in advance and tiny. It stops being safe the moment the action is *chosen* at
runtime — and that is exactly where the human is inserted.

---

### I2. What is the weakest part of this project?

I would name three honestly:

1. **Correlation is declared, not learned.** A human wrote down which metrics go
   together. A real system would learn it — but that needs weeks of labelled data
   this machine does not have.
2. **One threshold set for one machine.** The config is tuned for this VM.
3. **User timers stop when the session ends.** `Linger=no`; fixing it needs root.

---

### I3. What would you do next, with more time?

- Group correlated incidents across *types*, not just within one.
- Alerting — the project detects and explains but cannot yet tell anybody.
- Multi-host — everything assumes one machine.

---

### I4. Show me something the tests caught that you would not have.

Three, briefly:

1. **The zero-variance blind spot** — a 20× traffic spike reported as NORMAL (F8).
2. **`reject()` could never work.** `WAITING_APPROVAL → INVESTIGATING` was missing
   from the transition table, so the only exits from an approval request were to
   approve, resolve or ignore. **A state machine that pressures the operator into
   agreeing is the opposite of what an approval step is for.**
3. **The disappearing symptom list.** `INC-0003` finished recorded as
   `symptoms: load_5min` while its timeline said it opened on `cpu_idle_ticks,
   processes_running` — each update *overwrote* the list with whatever was
   abnormal at that instant, and the last instant of a recovering incident is the
   least informative there is. Fixed: `symptoms` is now the **union over the
   incident's whole life**.

---

### I5. You claim `guardian_rootcause.py` cannot run commands. Prove it.

`test_rootcause.py` parses the file into an **abstract syntax tree** and asserts
that neither `subprocess` nor `os` appears in any import node.

**Follow-up — "why not just `grep`?"**
Because the first version of that test *did* grep, and it **failed on the file's
own docstring** — which contains the words "subprocess" and "os" in the sentence
promising it never uses them. A text search cannot tell a comment from code; an
AST can.

---

### I6. How do you know a repair actually worked?

**Short answer:** By measuring again, never by reading the exit code.

`test_remediate.py` stubs an action that reports `status: ok` while
`check_service` reports the unit dead — a situation a real `systemctl` cannot be
made to produce on demand. Verification re-measures and catches it: the incident
goes to FAILED, stays open, and the timeline says *"no retry will be attempted"*.

---

### I7. Could someone forge a POST and approve their own remediation?

**Short answer:** They would gain nothing.

`approve()` takes an **incident id and an action id, and nothing else** — the test
suite asserts the function signature has no parameters parameter. Then:

1. The action id is checked against **that incident type's own** recommended list.
2. Every parameter is derived **server-side** from the root-cause result
   intersected with `HEALABLE_SERVICES`.
3. The registry validator runs again.
4. `healing.sh` checks everything from scratch.

Four independent checks, none trusting the others. **Refusals are written to the
incident's timeline** — a refusal is evidence, not an error to discard.

---

### I8. Why does root-cause analysis sometimes refuse to name a cause?

**Short answer:** Because sometimes there isn't one.

A process must account for at least `DOMINANCE_SHARE` (50 %) of measured CPU
before it is called dominant. Otherwise the finding is *"no single process
dominates"* at low confidence. Confidence is capped at 0.95, because a root cause
is an inference from one reading taken after the fact — never a proof.

The generic interpreter says *"no interpreter is written for this component"*
rather than templating confident prose, which would be a guess in the costume of
an analysis.

**Follow-up — "why three separate lists?"**
FACT / INFERENCE / RECOMMENDATION are different **kinds of statement**. A reader
must always be able to see which parts were measured and which were reasoned. One
merged paragraph hides that.

---

### I9. You wrote 426 tests. Are they real tests or just printing?

They are demonstrations that **exit non-zero on any failure**, so they work as
regression checks. The style is deliberate: they print a readable table of each
hostile input and the exact sentence the validator answers with, because the point
is to *show* what is refused, not to print a dot.

Some assert things a normal test cannot: that a file's parsed AST contains no
dangerous import; that the database file **on disk actually shrinks** after a prune
(the first version passed every row-count check while reclaiming nothing).

---

### I10. Tell me about a defect you found by looking rather than by reading.

Four, all from screenshotting the pages:

1. A CSS class name collision — `.pipeline .note` inherited the site-wide `.note`
   callout, so every lifecycle step grew a blue bordered box. Invisible in the
   markup.
2. `flex: 1 1 auto` on a card title **wrapped instead of shrinking**, stranding
   the ▸ marker alone above it — but only on cards whose title ran to two lines,
   so half the grid looked different for no visible reason. A wrapping flex
   container moves an item to the next line *before* it will shrink it;
   `flex-basis: 0` is the fix.
3. A metric constant at zero got a chart axis running from **−1 to 1**, because
   the flat-series branch skipped the non-negative guard — a chart asserting that
   a count could be negative.
4. The approval panel printed **Python literals** at the user:
   `{"service": "apache2"}` and `[['Will start', 'apache2.service'], …]`.

---

### I11. If I deleted `guardian.conf`, what would happen?

**Short answer:** Every module would refuse to run and say why — it fails loudly,
not silently.

Each script checks for the file before sourcing it:

```bash
CONFIG_FILE="$PROJECT_ROOT/config/guardian.conf"
[[ -r "$CONFIG_FILE" ]] || emit_error "config file not found or not readable: $CONFIG_FILE"
```

`emit_error` prints the standard error JSON and exits 1, so the web page shows an
error card naming the missing file. Nine of the ten scripts do this; the daemon
handles it in its own startup check.

**Follow-up — "but you also write `${DISK_WARNING:-80}`. Isn't that a default?"**
Yes, but for a *different* failure. Those 40 defaults cover **one key missing from
a config file that exists** — someone deletes a line, and the script keeps working
with a sensible value. A missing **file** is a different situation: it means the
installation is broken, and guessing every policy value silently would be the
wrong answer.

**Follow-up — "why is failing better than running with defaults?"**
Because the config holds `PROTECTED_SERVICES` and `HEALABLE_SERVICES`. A tool that
invents its own safety policy when it cannot find the real one is a tool that
might heal something it was told never to touch. Refusing is the safe direction.

---

## Quick revision card

| Question | One-line answer |
|---|---|
| CPU % | `/proc/stat` twice, 1 s apart, `100 × (1 − Δidle/Δtotal)` |
| Memory % | `/proc/meminfo`, `MemAvailable` not `MemFree` |
| Disk % | `df -P -k`, `-P` stops row wrapping |
| Load | `/proc/loadavg`, divided by `nproc` for per-core |
| Processes | `/proc/<pid>/stat` twice — not `top`, which truncates names |
| Services | `systemctl show`, machine-readable, not `status` |
| Live updates | `fetch("/api/overview")` every 10 s, text rewritten in place |
| Failed fetch | Nothing overwritten; the clock goes stale |
| Assistant | text → **id** → validate → argv **list** → `shell=False` |
| Write actions | Preview, then a confirm that re-validates from scratch |
| Security core | A request supplies a **name**, never a command |
| Anomaly | Statistical (3σ) **and** material (10 %) must both pass |
| Confidence | Chebyshev — true for any distribution, not a bell curve |
| Incident | One cause, one incident, many symptoms |
| Verification | Re-measure; an exit code is never proof |
