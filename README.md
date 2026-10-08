# Container SBOM pipeline

Builds a software bill of materials (SBOM) for container images, tracks what changes
between scans, and puts the container inventory and its vulnerabilities into Wazuh next to
the host inventory that Syscollector already collects.

It runs in two modes that share the same Trivy pin, event format and Wazuh rules:

- **Registry mode** (`scan_registry.py`): lists tags in container registries, pulls each
  image once, scans it, sends the findings to Wazuh and deletes the image. Runs hourly.
  See [Registry mode](#registry-mode).
- **Host mode** (`scan_all.py`): scans the images already on a host. Runs nightly.

Built for SWERI's Software Supply Chain Security placement (INFO3017, Group 8, 2026).

```
docker images ──► Trivy (pinned, cached DB) ──► out/<image>.json   CycloneDX SBOM per image
                                                     │
                                     scan_all.py compares it with the state in MongoDB
                                                     │
                  ┌────────── only what changed ─────┴─────── every scan ───────────┐
                  ▼                                                                  ▼
   /var/log/sbom/trivy-findings.jsonl                                 MongoDB  sweri_sbom
                  │  Wazuh agent (localfile)                                         │
                  ▼                                                                  ▼
   Wazuh manager, rules 100200-100207 ──► dashboard       reports, consolidated SBOM
```

Wazuh only receives changes. A nightly scan sends nothing unless something changed:
a package, the image, or a newly published CVE. The first scan of an image sends its full
inventory once (the *baseline*).

## Contents

| File | Purpose |
|---|---|
| `scan_registry.py` | Registry mode. Lists registry tags, then pulls, scans (with `scan_all.py`'s code) and removes one image at a time |
| `registries.json` | Registry mode config: which repos and tags to scan |
| `scan_all.py` | Host mode. Scans the images on a host, tracks changes, feeds Wazuh, writes per-image reports |
| `report.py` | Markdown vulnerability summary for one image |
| `export_cyclonedx.py` | One consolidated CycloneDX SBOM file for every scanned image (deliverable 3) |
| `gap_analysis.py` | Wazuh Syscollector (host) vs Trivy (container) inventory comparison (deliverable 4) |
| `sbom_common.py` | Shared settings and helpers; reads `.env` |
| `.env.example` | Template for the machine's settings (copy to `.env`) |
| `wazuh/sbom_rules.xml` | Manager rules for the pipeline's events |
| `wazuh/agent_localfile_block.xml` | Agent config that reads the event log |
| `deploy/` | systemd units (`sbom-registry.*` hourly, `sbom-scan.*` nightly); logrotate config |
| `tests/` | Unit tests (`python3 -m pytest`) |

## Setup (once per host)

Run these steps on the host whose images you want scanned, unless a step says otherwise.
The lab host is `sweri-node-01`.

**1. Prerequisites.** You need Docker, Python 3.10 or newer, and git. The user that runs
the pipeline must be in the `docker` group. That gives it root-equivalent access, so use a
dedicated user if you can.
```bash
sudo usermod -aG docker $USER        # then log out and back in
git clone https://github.com/Brilofori/sbom-project.git && cd sbom-project
pip install -r requirements.txt
cp .env.example .env && chmod 600 .env    # this machine's settings; see Configuration
```

**2. MongoDB.** If the machine already runs MongoDB, skip this step and put its address in
`.env` (`SBOM_MONGO_URI`) unless it is on localhost without a password. Otherwise, start one
bound to localhost only, with its data in a named volume and the version pinned. Docker's `-p 27017:27017` publishes on every interface and bypasses UFW, and
this MongoDB has no authentication.
```bash
docker run -d --name mongodb --restart unless-stopped \
  -p 127.0.0.1:27017:27017 -v sbom-mongo-data:/data/db mongo:8.0
```

**3. Trivy image.** `scan_all.py` runs Trivy 0.74.0, pinned by digest (`TRIVY_IMAGE`). The
first run pulls it if it isn't present. To check it:
```bash
docker run --rm aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 --version
```
To move to a new Trivy release, review it first (see the Trivy Security Assessment,
deliverable 2). Then get its digest with
`docker image inspect aquasec/trivy:<version> --format '{{index .RepoDigests 0}}'` and
either update `TRIVY_IMAGE` or set `SBOM_TRIVY_IMAGE`.

**4. Event log directory.** The pipeline writes Wazuh events here.
```bash
sudo mkdir -p /var/log/sbom && sudo chown $USER /var/log/sbom
```

**5. Wazuh agent (this host).** Add the block from `wazuh/agent_localfile_block.xml` inside
`<ossec_config>` in `/var/ossec/etc/ossec.conf`, then run `sudo systemctl restart wazuh-agent`.

**6. Wazuh manager.** Install the rules, check the syntax, and restart:
```bash
sudo cp wazuh/sbom_rules.xml /var/ossec/etc/rules/sbom_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/sbom_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
If these rules were ever pasted into `local_rules.xml`, delete them from there first.
Duplicate rule IDs stop `wazuh-analysisd` from starting.

**7. First run.** Run `python3 scan_all.py`. See [Running](#running).

**8. Schedule it.** Use the systemd timer in `deploy/`. It runs nightly at about 02:30,
and catches up after the machine was off:
```bash
# edit User= and the paths in deploy/sbom-scan.service first
sudo cp deploy/sbom-scan.service deploy/sbom-scan.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sbom-scan.timer
systemctl list-timers sbom-scan.timer          # next run
journalctl -u sbom-scan.service                # output of past runs
```
Cron works too: `30 2 * * * cd /home/<user>/sbom-project && /usr/bin/python3 scan_all.py >> /var/log/sbom/pipeline.log 2>&1`.

**9. Log rotation.** Run `sudo cp deploy/logrotate-sbom /etc/logrotate.d/sbom`. It rotates by
renaming the file. Never use `copytruncate` on the event log: truncating a file Wazuh
monitors fires rule 592, "Log file size reduced" (level 8), on every rotation.

## Running

```bash
python3 scan_all.py                     # every tagged image on this host (except Trivy itself)
python3 scan_all.py images.txt          # only the images listed (one per line, # comments ok)
python3 scan_all.py --rebaseline        # set state aside and resend the full inventory once
```
The run exits 1 if any image failed, so cron and systemd report failures. One broken
image doesn't stop the others. Only one scan runs at a time, in either mode (both scanners
take the same lock); a second run exits immediately.

Each run does the following:

- Downloads the Trivy vulnerability DB once, into the `trivy-cache` Docker volume, so
  every image in the run is scanned against the same DB.
- Scans each image with Trivy and saves the CycloneDX output as `out/<image>.json`. A
  failed scan keeps the previous good file.
- Compares the scan with the stored state and appends the changes to the Wazuh event log.
- Saves the scan and writes `out/report_<image>.md`.

Other tools:
```bash
python3 report.py python:3.11-slim [out.md]         # vulnerability summary for one image
python3 export_cyclonedx.py                         # out/sweri-consolidated.cdx.json
python3 gap_analysis.py wazuh_inventory.txt --image python:3.9-slim
```
For `gap_analysis.py`, first export the host inventory on the Wazuh manager. Agent `001` is
the scanned host; the command is also in the script's header.
`sudo sqlite3 /var/ossec/queue/db/001.db "SELECT name, version FROM sys_programs;" > wazuh_inventory.txt`

## Registry mode

`scan_registry.py` scans images straight from container registries, so the scanning host
doesn't need to keep them. Each pass:

1. Lists the tags of every repo in `registries.json` that match its filters, with the digest
   each tag points to.
2. Skips any image + tag + digest already scanned. A tag is scanned again only when it is
   rebuilt (new digest).
3. For each new image: pull it, then scan it and send the changes to Wazuh with
   `scan_all.py`'s own code (same Trivy settings, 30-minute limit, parsing and change
   tracking), record it, then remove the image. Only one image is on disk at a time, so the
   host needs free space for the largest image plus Trivy's scratch space (about twice the
   image size).

Images that were already on the host before the pass are never removed. An image that fails
is retried on the next pass, up to 3 times.

```bash
python3 scan_registry.py --dry-run      # list what would be scanned, pull nothing
python3 scan_registry.py                # one pass
```

**Config.** Each entry in `registries.json` names a repo and which of its tags to scan:
```json
{"repo": "python", "include": "^3\\.\\d+\\.\\d+-slim$", "limit": 5, "platform": "linux/amd64"}
```
`include` and `exclude` are regular expressions on the tag, `limit` keeps the newest N
matching tags. Anonymous Docker Hub pulls are rate-limited, so run `docker login` with a
free account on the scanning host.

**Private registries.** Any registry that speaks the Docker Registry v2 API works: Harbor,
GitLab, Nexus, Artifactory, a plain `registry:2`. Set `registry` to its `host:port`; a
repo entry can also set its own `registry`, so one config can cover several:
```json
{
  "registry": "registry.sweri.local:5000",
  "platform": "linux/amd64",
  "repositories": [
    {"repo": "ml/inference-server", "include": "^\\d+\\.\\d+\\.\\d+$", "limit": 5},
    {"repo": "redis", "registry": "docker.io", "include": "-alpine$", "limit": 2}
  ]
}
```
On the scanning host, as the user the scanner runs as:
1. `docker login registry.sweri.local:5000` with a read-only account (a robot account in
   Harbor). The scanner reads the same saved login to list tags. If Docker uses a
   credential helper instead, put `SBOM_REGISTRY_USER` and `SBOM_REGISTRY_PASSWORD` in
   `.env`.
2. If the registry's certificate comes from an internal CA, install the CA for both Docker
   (`/etc/docker/certs.d/registry.sweri.local:5000/ca.crt`) and the OS
   (`/usr/local/share/ca-certificates/`, then `sudo update-ca-certificates`).
3. A registry on plain HTTP needs `"insecure": true` in the config and an
   `insecure-registries` entry in `/etc/docker/daemon.json`. Avoid this outside a lab.

The v2 API lists tags alphabetically with no dates, so "newest" means the highest version
number (1.10 above 1.9). Use `include` to keep tags like `latest` or `dev-*` out.
Run `--dry-run` first: it lists the tags and digests without pulling anything, and a bad
login or certificate shows up there.

**Schedule.** Setup steps 1 to 6 apply here too. Then:
```bash
sudo cp deploy/sbom-registry.service deploy/sbom-registry.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sbom-registry.timer
systemctl list-timers sbom-registry.timer
tail -f /var/log/sbom/registry.log
```
The timer runs 5 minutes after boot, then hourly.

**Events.** Same format and rules as host mode, plus `scanner_mode: "registry"`,
`registry` and `digest`. In the Wazuh dashboard, `data.scanner_mode:registry` shows only
registry-mode events; add `and data.sbom_event:component` for one row per package per image.

**State.** `registry_scans` has one document per image + tag + digest, with its status and
attempt count; that's what decides what to scan. Everything else is shared with host mode:
change tracking in `component_state` and `vuln_state`, scans in `scans` (with
`scanner_mode: "registry"`), the latest CycloneDX file per image in `out/registry/`. So
`report.py`, `export_cyclonedx.py` and `gap_analysis.py` work on registry images too.

**Limitation.** An image is scanned once per digest. A CVE published after that scan is not
reported until the tag is rebuilt. Host mode catches these on its nightly re-scan
(`cause: db_update`); registry mode doesn't yet.

## How change detection works

**Package identity.** State is tracked per host, per image, per *package identity*: the
purl without its version or qualifiers.
`pkg:deb/debian/libc6@2.36-9+deb12u7?arch=amd64&distro=debian-12.7` becomes
`pkg:deb/debian/libc6`. Trivy's purls include the version and the OS point release, so
tracking on the raw purl would make every base-image refresh look like hundreds of new
packages and CVEs. With identities, a refresh shows up as a few `component_changed` events.

**Events sent to Wazuh.** Every event has `source: "trivy"`, `host`, `image`, `image_id`,
`identity`, `package_name` and `timestamp`.

| `sbom_event` | Rule | Level | When |
|---|---|---|---|
| `component` | 100201 | 3 | A package appears: baseline, newly added, or re-added (`cause`) |
| `component_changed` | 100205 | 3 | A package's version changed (`previous_version`, then `installed_version`) |
| `component_removed` | 100206 | 3 | A package is no longer in the image |
| `vulnerability` | 100202 / 100203 / 100204 | 5 / 10 high / 12 critical | A CVE appears on a package |
| `vulnerability_resolved` | 100207 | 3 | A reported CVE is gone: fixed, or its package removed |

**Why a vulnerability is new (`cause`).**

| `cause` | Meaning |
|---|---|
| `baseline` | First scan of this image on this host |
| `image_changed` | The image was rebuilt or re-pulled since the last scan (different image ID) |
| `db_update` | Same image ID. Nothing in the image changed; the CVE is newly published or newly matched |
| `regression` | This CVE was resolved earlier and is back |

**Severity.** `severity` is the severity Trivy itself reports. It takes the rating from the
package's own distribution (e.g. Debian's for a Debian package), then GitHub Advisory for
GHSA IDs, then NVD. `max_severity` is the worst rating from any source, including other
distributions' ratings of their own builds. The rules alert on `severity`, so the numbers
match what `trivy image` shows. To alert on the worst case instead, change the rules to use
`max_severity`.

**Fixes.** `fixed_version` comes from Trivy's `recommendation` field, which is the only
place Trivy writes it.

**Delivery.** Events are written and fsynced before the state is saved. If the write
fails, nothing is marked as seen, and the next run sends the events again. A crash between
the write and the save can produce a duplicate, but never loses an event. Writes are
throttled to 400 lines per second (`SBOM_WAZUH_EPS`). The agent forwards 500 per second by
default and drops anything beyond its buffer, which matters for the baseline of a large
image.

## Data in MongoDB (`sweri_sbom`)

| Collection | One document per | Key fields |
|---|---|---|
| `scans` | scan | `host`, `image`, `scanned_at`, `scanner_mode`/`registry`/`digest` (registry mode), `image_id`, `os`, `scanner_version`, `db_updated_at`, counts, `components[]`, `vulnerabilities[]` (per CVE+package: `severity`, `max_severity`, `fixed_version`, `is_new`, `cause`), `resolved[]` |
| `component_state` | host + image + package identity | `versions`, `present`, `first_seen`, `last_seen`, `removed_at` |
| `vuln_state` | host + image + CVE + package identity | `status` (open/resolved), `severity`, `fixed_version`, `first_seen`, `opened_at`, `resolved_at` |
| `cve_info` | CVE | `description`, `published`, `updated`, `source` |
| `registry_scans` | registry image + digest (registry mode only) | `repo`, `tag`, `registry`, `status` (ok/failed), `attempts`, `error`, counts |

CVE descriptions are stored once in `cve_info` instead of in every scan. This keeps big
images well under MongoDB's 16MB document limit. If a scan still exceeds the limit, it is
saved without its per-CVE list and flagged `truncated`.

## Configuration

| Variable | Default | |
|---|---|---|
| `SBOM_MONGO_URI` | `mongodb://localhost:27017` | |
| `SBOM_DB` | `sweri_sbom` | |
| `SBOM_OUT_DIR` | `<repo>/out` | SBOM files, reports, lock file |
| `SBOM_TRIVY_IMAGE` | Trivy 0.74.0 by digest | |
| `SBOM_TRIVY_CACHE` | `trivy-cache` | Docker volume for Trivy's DB |
| `SBOM_WAZUH_LOG` | `/var/log/sbom/trivy-findings.jsonl` | Must match the agent's `<location>` |
| `SBOM_WAZUH_EPS` | `400` | Event lines per second |
| `SBOM_REGISTRY_USER`, `SBOM_REGISTRY_PASSWORD` | the `docker login` entry | Registry mode, private registries |

Put the settings for a machine in `.env` in the repo folder (start from `.env.example`):
one `KEY=value` per line, comments on their own line. Every script reads it, whether run
by hand or by the systemd timers, and git ignores it. Run `chmod 600 .env` if it holds a
password; error messages hide the MongoDB password. A variable set in the environment
overrides `.env`, e.g. `SBOM_DB=test python3 scan_all.py`.

## Upgrading an install that ran the September 2026 version

1. **Pull the new code, then update Wazuh.** Update the manager rules (setup step 6) and
   the agent block (step 5), and add `<only-future-events>no</only-future-events>`.
2. **Recreate MongoDB bound to localhost, keeping its data.** Step 2 above is for a new
   install; use these commands here instead.
   ```bash
   docker inspect mongodb --format '{{range .Mounts}}{{if eq .Destination "/data/db"}}{{.Name}}{{end}}{{end}}'
   docker exec mongodb mongod --version | head -1       # stay on this major version
   docker stop mongodb && docker rename mongodb mongodb-old
   docker run -d --name mongodb --restart unless-stopped -p 127.0.0.1:27017:27017 \
     -v <volume-name-from-line-1>:/data/db mongo:<major.minor-from-line-2>
   # after a successful scan: docker rm mongodb-old
   ```
3. **Run `python3 scan_all.py`.** The old state was keyed on the full purl, so it is renamed
   to `vuln_state_legacy` and `component_state_legacy` (kept, not deleted). This run then
   **re-sends the full inventory once**, with `cause: baseline`, so expect one batch of
   alerts. It also restores anything that was sent before the rules were loaded on the
   manager, which only ever reached the archives. Once satisfied, drop the legacy
   collections with
   `docker exec mongodb mongosh sweri_sbom --eval 'db.vuln_state_legacy.drop(); db.component_state_legacy.drop()'`.

## Known limitations

- **Conda.** Trivy lists Conda packages only from named environments
  (`<conda>/envs/<name>/`), not the base environment, and never matches vulnerabilities for
  Conda packages. ML images that install into `/opt/conda` can therefore miss their Conda
  layer. Pip-installed packages (`.dist-info`) are covered. To check an image, run
  `docker run --rm --entrypoint sh <image> -c 'ls /opt/conda/envs; ls /opt/conda/conda-meta | wc -l'`.
- **Only local images are scanned, by tag.** A tag like `:latest` can point to a different
  image later. The image ID recorded with every scan shows when it moved.
- **Single architecture.** Scans run on the host's architecture (x86_64 in the lab).
- **Scanner coverage.** Coverage and severity data are Trivy's. No second scanner (e.g.
  Grype) cross-checks the results yet.
- **No MongoDB authentication in the lab setup.** It relies on the localhost binding. To use
  a remote MongoDB, set `SBOM_MONGO_URI` (with user, password and `tls=true`) in
  `.env`. Several hosts can share one database, because all state
  is keyed per host.
- **Very large images are slow.** A 15GB ML image overran Trivy's default 5-minute timeout,
  so the pipeline allows 30 minutes per image. Its baseline sends several thousand events at
  the throttled rate.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied ... Docker daemon socket` | Add the user to the `docker` group (setup step 1) and log in again |
| `Cannot write the Wazuh log` | Setup step 4 |
| `Cannot reach MongoDB` | `docker start mongodb`, then check `docker logs mongodb` |
| `scan failed: ... context deadline exceeded` | Image too large for the 30-minute timeout; raise `--timeout` in `scan_image` |
| Events in the log but nothing in the dashboard | On the manager, run `sudo /var/ossec/bin/wazuh-logtest` and paste a line from the event log. It should match a rule in 100201–100207. If not, check setup step 6. On the agent, check `grep -i sbom /var/ossec/logs/ossec.log` |
| `Agent event queue is full` alerts | Lower `SBOM_WAZUH_EPS`, or raise `<client_buffer>` on the agent |
| Rule 592 "Log file size reduced" | Something truncated the event log. Use the logrotate config, and don't `>` the file |

Check the most recent events:
`tail -n 3 /var/log/sbom/trivy-findings.jsonl | python3 -m json.tool --json-lines`

## Security notes

- Trivy runs with `/var/run/docker.sock` mounted, which gives it root-equivalent control
  of Docker. That's why the image is pinned by digest and updated only after review.
- The pipeline user is in the `docker` group, which is also root-equivalent. Treat the
  user accordingly.
- MongoDB listens on 127.0.0.1 only. Keep it that way unless you add authentication.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```
The tests use fixtures shaped like Trivy 0.74's CycloneDX output and an in-memory MongoDB
(mongomock). They cover:

- parsing, including fixed versions and severity selection;
- every change-tracking case (point-release rebuild, fix, removal, regression, new DB data,
  multiple hosts, failed delivery, legacy migration);
- reports, the gap analysis, and schema validation of the consolidated SBOM (when
  `cyclonedx-python-lib[json-validation]` is installed).
