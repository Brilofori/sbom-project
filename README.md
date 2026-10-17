# Container SBOM Pipeline

Scans container images for the software packages inside them and the known
vulnerabilities in those packages, keeps a record of every image, and sends Wazuh an
alert whenever something changes.

Wazuh already records the software installed on each machine. It does not look inside
container images. This pipeline fills that gap, so container packages and their
vulnerabilities appear in the same Wazuh dashboard as everything else.


## How it works

Four parts work together. They can sit on one machine or on several, as long as they can
reach each other over the network.

```
  Container registry ──images──►  Scanning machine  ──results──►  MongoDB
  (where the images are)          (runs this code,
                                   Docker and Trivy)  ──alerts───►  Wazuh manager
```

- **Container registry.** Where the images are stored, such as Harbor, Azure Container
  Registry, GitLab or Docker Hub.
- **Scanning machine.** Runs this code. For each image it downloads the image, unless the
  machine already has it, has [Trivy](https://trivy.dev) list every package and
  vulnerability in it, then deletes what it downloaded.
- **MongoDB.** Keeps every scan and remembers what each image contained last time.
- **Wazuh manager.** Receives an alert for each change, through the Wazuh agent on the
  scanning machine.

**Only changes are sent to Wazuh.** The first scan of an image sends its full contents once.
After that, Wazuh hears about an image only when something changes: a package is added,
removed or upgraded, the image is rebuilt, or a new vulnerability is published that affects
it. A scan that finds nothing new sends nothing.

### Three ways to run it

- **Registry mode** (`scan_registry.py`) scans the images in a registry. It downloads one
  image at a time, scans it and deletes it, so the scanning machine never stores more than
  one downloaded image. An image the machine already has is scanned where it is, and never
  deleted. Images are downloaded by their digest (the registry's fingerprint for that exact
  image), so a tag on the machine never changes. Each image is scanned once, and again only
  when it is rebuilt. Runs hourly.
- **Host mode** (`scan_all.py`) scans the images already on the scanning machine, and never
  downloads anything. It re-scans all of them each time, which is how it notices newly
  published vulnerabilities in images that haven't changed. Runs nightly.
- **Both at once** (`scan_registry.py --local`) is for a machine that has images of its own
  and should also cover a registry, such as a build server that pushes to it. Each run
  first scans every image on the machine, as host mode does, then scans from the registry
  only the images the machine doesn't have.

All three produce the same results and alerts. Run one of them per machine: where a machine
has its own images and also needs a registry covered, use `--local` rather than both
scanners, so that each image is reported from one place.

**Each image is scanned once, under one name.** An image often has several tags, such as
`1.4.2` and `latest`, or a short local name as well as its name in the registry. It is
scanned once and reported under one of them; the others are listed in each alert, under
`other_tags`. The name chosen is a fixed version rather than `latest`, since `latest` moves
to the next build, and a name with the registry's address rather than one without. An
image keeps the name it was reported under for as long as it has that tag. If that tag
moves on to a newer build or is removed, the image carries on under one of its other tags
and takes its record with it, so nothing about it is sent again.


## Setting it up on a new site

No code needs to change. Setting up means telling the pipeline where each part is. These
are the six things to set, and where each one goes.

**1. The registry to scan.**
In `registries.json`, the `registry` line. (`registries.json` starts as a copy of
`registries.example.json`.) Give the address without `https://`, for
example `"registry": "registry.example.com"` or `"registry": "10.0.0.4:5000"`.

**2. Which images to scan in it.**
Nothing to do: by default every image in the registry is scanned, the newest two versions
of each. To scan only some, see [Choosing what to scan](#choosing-what-to-scan).

**3. The login for the registry.**
On the scanning machine, logged in as the user that runs the scanner, run
`docker login registry.example.com` with a read-only account. The scanner reuses that
saved login.

**4. Where MongoDB is.**
In `.env`, the `SBOM_MONGO_URI` line. Leave it alone if MongoDB runs on the scanning
machine. Otherwise give its address, for example `SBOM_MONGO_URI=mongodb://10.0.0.5:27017`.

**5. Which database to use in MongoDB.**
In `.env`, the `SBOM_DB` line. The default is `sweri_sbom`. Choose another name if that one
is already used for something else.

**6. Where Wazuh is.**
This is set in the Wazuh agent on the scanning machine, not in this code: the
`<server><address>` line in `/var/ossec/etc/ossec.conf`. It is normally filled in when the
agent is installed.

`.env` starts as a copy of `.env.example`, which explains each setting. Everything else has
a working default; the full list is under [All settings](#all-settings).


## Installing

Follow these steps on the scanning machine unless a step says otherwise.

**Step 1. Check the machine has what it needs.**
Docker, git and Python 3.10 or newer, plus network access to the registry, MongoDB and the
Wazuh manager. Allow free disk space of about five times the download size of the largest
image, plus 10 GB: Docker keeps each image unpacked while it is scanned, and Trivy makes a
second copy to scan. For registries that report image sizes (most private registries, not
Docker Hub), registry mode checks this before each download and skips an image that
wouldn't fit. The full list, including network ports, is at the
top of `requirements.txt`.

**Step 2. Create a user for the scanner and give it access to Docker.**
```bash
sudo useradd -m sbom
sudo usermod -aG docker sbom
sudo mkdir /opt/sbom-project && sudo chown sbom /opt/sbom-project
```
Membership of the `docker` group gives full control of Docker, which is equivalent to root
access. Use this account only for the scanner.

**Step 3. Get the code and the Python packages.** Switch to the `sbom` user with
`sudo -iu sbom`, and do the rest of the installation as that user unless a step uses
`sudo`.
```bash
git clone <repository-url> /opt/sbom-project
cd /opt/sbom-project
pip install -r requirements.txt
```

**Step 4. Fill in the settings.**
```bash
cp .env.example .env
chmod 600 .env
cp registries.example.json registries.json
```
Then edit `.env` and `registries.json` as described in
[Setting it up on a new site](#setting-it-up-on-a-new-site).

**Step 5. Start MongoDB, unless the site already has one.**
```bash
docker run -d --name mongodb --restart unless-stopped \
  -p 127.0.0.1:27017:27017 -v sbom-mongo-data:/data/db mongo:8.0
```
This MongoDB has no password, so it only accepts connections from the same machine
(`127.0.0.1`). If the site already runs MongoDB, skip this step and put its address in
`.env` instead.

**Step 6. Create the folder for the Wazuh alerts.**
```bash
sudo mkdir -p /var/log/sbom
sudo chown sbom /var/log/sbom
```

**Step 7. Tell the Wazuh agent to read the alerts.**
Copy the block from `wazuh/agent_localfile_block.xml` into `/var/ossec/etc/ossec.conf`,
inside `<ossec_config>`, then run `sudo systemctl restart wazuh-agent`.

**Step 8. Install the alert rules on the Wazuh manager.** On the manager:
```bash
sudo grep -rn 'id="1002' /var/ossec/etc/rules/       # rule IDs 100200-100210 must be free
sudo cp sbom_rules.xml /var/ossec/etc/rules/sbom_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/sbom_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
The rules file is `wazuh/sbom_rules.xml` in this repository; copy it to the manager first.
If the first command finds rules already using those IDs, the IDs in `sbom_rules.xml` need
changing before it is installed.

**Step 9. Check the settings, then run a first scan.**
```bash
python3 scan_registry.py --dry-run
python3 scan_registry.py
```
The dry run lists every image that would be scanned, without downloading anything. A wrong
address, login or certificate shows up here. The second command scans for real. On a machine
with images of its own, add `--local` to both commands.

**Step 10. Schedule it.**
In `deploy/sbom-registry.service`, check the `User=` and `WorkingDirectory=` lines match
steps 2 and 3. Then:
```bash
sudo cp deploy/sbom-registry.service deploy/sbom-registry.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sbom-registry.timer
sudo cp deploy/logrotate-sbom /etc/logrotate.d/sbom
```
The scanner now runs five minutes after the machine starts, then every hour. On a machine
that also has images of its own, such as a build server, add `--local` to the end of the
`ExecStart=` line first. For host mode, use `sbom-scan.service` and `sbom-scan.timer` in the
same way; that runs nightly at about 02:30.


## Choosing what to scan

By default the scanner finds every image in the registry by itself. `registries.json` only
needs the registry's address:

```json
{
  "registry": "registry.example.com",
  "platform": "linux/amd64",
  "include": "^\\d+\\.\\d+\\.\\d+$",
  "limit": 2
}
```

On each run it asks the registry for its full list of images, and scans the two newest
versions of each one. New images added to the registry are picked up on the next run, with
no change to the file.

- **`registry`** is the registry's address, without `https://`.
- **`platform`** is the type of processor the images are built for: `linux/amd64` for
  ordinary Intel and AMD servers, `linux/arm64` for ARM. Versions with no image for it are
  skipped.
- **`include`** chooses which versions (tags) count. `^\\d+\\.\\d+\\.\\d+$` matches
  plain version numbers such as `1.4.2`, and so skips tags like `latest` or `dev`. Leave it
  out to consider every tag.
- **`exclude`** skips versions, in the same way. For example `"exclude": "-rc"` skips
  release candidates.
- **`limit`** is how many versions to scan per image, newest first. The default is 5.
- **`exclude_repos`** skips whole images by name. For example `"exclude_repos": "^test/"`
  skips everything under `test/`.
- **`insecure`** is only for a registry without HTTPS, such as a test setup. Docker on the
  scanning machine then also needs the registry listed under `insecure-registries` in
  `/etc/docker/daemon.json`. Leave it out otherwise.

`include`, `exclude` and `exclude_repos` are regular expressions, and the backslashes are
doubled because the file is JSON. "Newest" means the highest version number, so `1.10`
counts as newer than `1.9`. After changing the file, run `python3 scan_registry.py --dry-run`
to see what it selects.

**Finding every image needs permission to list them.** The registry login must be allowed
to see the registry's list of images, not only to download them. If it isn't, the dry run
says it could not list the repositories. Either give the account that permission, or name
the images instead, as below.

**Naming the images instead.** To scan only certain images, list them under
`repositories`. Each entry can have its own `include`, `exclude` and `limit`, and its own
`registry`, so one file can cover several registries:

```json
{
  "registry": "registry.example.com",
  "repositories": [
    {"repo": "ml/inference-server", "limit": 3},
    {"repo": "ml/trainer", "exclude": "-rc", "limit": 2}
  ]
}
```

`repo` is the image's name as the registry shows it, without the registry address or a
version. Docker Hub can't list all its images, so scanning from Docker Hub always needs a
`repositories` list; it also limits how often anonymous users can download, so run
`docker login` with a free Docker Hub account.

**Registries with their own certificate authority.** If the registry's HTTPS certificate is
issued by an internal certificate authority, install that authority's certificate for Docker
(`/etc/docker/certs.d/registry.example.com/ca.crt`) and for the operating system
(`/usr/local/share/ca-certificates/`, then `sudo update-ca-certificates`).

**Logins that expire.** Some registries hand out logins that stop working after a few
hours, such as the one `az acr login` creates for Azure Container Registry. Use a long-lived
read-only account instead, for example an ACR token or service principal, or the hourly
scans will start failing.


## Running it by hand

Registry mode:
```bash
python3 scan_registry.py --dry-run       # show what would be scanned
python3 scan_registry.py                 # scan once
python3 scan_registry.py --local         # this machine's images first, then the registry
python3 scan_registry.py --retry-failed  # also retry images it gave up on (see "giving up on")
```

Host mode:
```bash
python3 scan_all.py                      # every image on this machine
python3 scan_all.py images.txt           # only the images listed in the file, one per line
python3 scan_all.py --rebaseline         # forget previous results and resend everything once
```
Images listed in a file must be on the machine already; host mode never downloads them. A
name is reported the way Docker lists it, so `nginx` is reported as `nginx:latest`.

Only one scan runs at a time. If a scan is already running, in either mode, a second one
stops straight away. If any image fails, the others still run and the command ends with an
error, so the scheduler records the failure. In registry mode a failed image is tried again
on the next run, up to three times in all.

**The combined SBOM.** One CycloneDX file listing every package and vulnerability in every
scanned image, built from what is already stored in MongoDB. This is the file to give an
auditor or another security tool:
```bash
python3 export_cyclonedx.py              # writes out/sweri-consolidated.cdx.json
```

**Where the files go.** Everything is written to the `out` folder in the repository: the
latest SBOM of each image (`out/<image>.json`, and `out/registry/` for registry mode) and the
combined SBOM. A failed scan keeps the previous good file.


## What Wazuh receives

Each alert is one line of JSON, written to `/var/log/sbom/trivy-findings.jsonl` and passed
on by the Wazuh agent. Every alert names the machine (`host`), the image, and the package.
In the Wazuh dashboard, search for `data.sbom_event` to see them.

- **`component`** (rule 100201, level 3): a package is present in an image. Sent for every
  package on an image's first scan, then whenever a package is added.
- **`component_changed`** (rule 100205, level 3): a package was upgraded or downgraded. The
  alert gives the old and new version.
- **`component_removed`** (rule 100206, level 3): a package is no longer in the image.
- **`vulnerability`** (rules 100202 to 100204): a vulnerability affects a package in the
  image. The level depends on severity: 10 for high, 12 for critical, and 5 for anything
  lower. The alert includes the fixed version, when one exists.
- **`vulnerability_resolved`** (rule 100207, level 3): a vulnerability reported earlier no
  longer applies, because the package was fixed or removed.

Each vulnerability alert also says why it is new, in the `cause` field:

- **`baseline`**: the first scan of this image.
- **`image_changed`**: the image was rebuilt since the last scan.
- **`db_update`**: the image is unchanged; the vulnerability was published or matched
  since the last scan.
- **`regression`**: this vulnerability was fixed before and has come back.

Registry-mode alerts also carry `scanner_mode: "registry"`, the `registry` and the image's
`digest`. Alerts for an image with several tags carry `other_tags`: the tags it was not
reported under.

**Every run also sends one summary,** so you can tell from the dashboard that the scanner is
working, and see straight away when it isn't:

- **`scan_run`** (rule 100208, level 3): the run finished. It says how many images were
  scanned (`scanned`), how many failed (`failed`), and how the scanner was run
  (`scanner_mode`: `host`, `registry`, or `local+registry` for `--local`). In registry mode
  it also counts the tags it left alone (`skipped`) and the images it gave up on
  (`abandoned`); both are explained under [When something goes wrong](#when-something-goes-wrong).
- The same summary rises to **level 7** (rule 100209) when something went wrong but the run
  carried on: some images failed to scan, one image's versions couldn't be listed, or a
  downloaded image couldn't be removed afterwards. `errors` says what and why.
- It rises to **level 10** (rule 100210) when the run couldn't do its job at all: MongoDB
  was unreachable, the registry couldn't be read (usually an expired login), every image
  failed, or the scanner stopped on an unexpected error.

A run that sends findings but no summary was stopped from outside, for example by a
restart. `errors` is shortened to fit in a Wazuh alert; the full text is in the scanner's
log.
In registry mode with nothing new to scan, the summary is the only alert, which is how a
quiet hour can be told apart from a broken scanner.

**Severity** is the one Trivy reports. It takes the rating from the package's own
distribution first (for example Debian's rating for a Debian package), then GitHub's
advisory database, then the US National Vulnerability Database (NVD). `max_severity` is the worst
rating from any source, for anyone who prefers to alert on that instead.


## How changes are recognised

Packages are matched by name, not by name and version. Trivy's package identifiers include
the version, and for system packages even the operating system's point release, so
`pkg:deb/debian/libc6@2.36-9+deb12u7` changes on every base-image update. The pipeline
compares `pkg:deb/debian/libc6` instead. That way an update shows up as a few
`component_changed` alerts rather than hundreds of packages that seem to vanish and
reappear.

**No alert is lost.** Alerts are written to disk before the results are saved. If writing
fails, nothing is marked as sent, and the next run sends the alerts again. A crash at the
wrong moment can produce a duplicate alert, never a missing one.

**Large images don't flood Wazuh.** Alerts are written at up to 400 lines a second, below
the 500 a second the Wazuh agent forwards by default. The first scan of a large image can
produce several thousand alerts, which then take a few seconds to send.


## What is stored in MongoDB

Everything is in one database (`sweri_sbom` by default).

- **`scans`**: one record per scan, with the full package and vulnerability list, the
  image's ID, operating system, and the Trivy and vulnerability-database versions used. A
  short record marked `carried_from` isn't a scan: it notes that an image's record moved to
  a new name.
- **`component_state`**: one record per package per image, with its versions and when it
  was first and last seen.
- **`vuln_state`**: one record per vulnerability per package per image: open or resolved,
  and when.
- **`cve_info`**: one record per vulnerability, with its description. Kept separately so
  large images stay within MongoDB's 16 MB limit per record. A scan that still exceeds it is
  saved without its vulnerability list and marked `truncated`.
- **`registry_scans`**: registry mode only. One record per image version scanned, with
  whether it succeeded. This is how the scanner knows what it has already done. A tag that
  is the same image as one already scanned is recorded with `same_as`, the name the image
  was reported under.

`component_state` and `vuln_state` are kept under the name each image is reported under.
When an image's name changes, its records move with it; a name that becomes one of another
image's other tags loses its own records.

Results are kept per scanning machine, so several machines can share one database.

Results saved by the September 2026 version are in an older format. The first run moves
them aside to `vuln_state_legacy` and `component_state_legacy` (they are kept, not deleted)
and sends each image's contents once as a new first scan.


## All settings

Settings go in `.env` in the repository folder, one `NAME=value` per line. A setting given
on the command line takes priority, for example `SBOM_DB=test python3 scan_all.py`.

- **`SBOM_MONGO_URI`**: where MongoDB is. Default `mongodb://localhost:27017`. With a
  password: `mongodb://user:password@host:27017/?authSource=admin`, and add `&tls=true` if
  the database uses encrypted connections. The password is hidden in error messages.
- **`SBOM_DB`**: the database name. Default `sweri_sbom`.
- **`SBOM_REGISTRY_USER`** and **`SBOM_REGISTRY_PASSWORD`**: a registry login, used instead
  of the one saved by `docker login`. Only needed when Docker keeps logins somewhere the
  scanner can't read, such as a credential helper.
- **`SBOM_WAZUH_LOG`**: the file alerts are written to. Default
  `/var/log/sbom/trivy-findings.jsonl`. If changed, change the agent's `<location>` to
  match.
- **`SBOM_WAZUH_EPS`**: alerts written per second. Default 400.
- **`SBOM_OUT_DIR`**: where scan files and the combined SBOM are written. Default the `out` folder in
  the repository.
- **`SBOM_TRIVY_IMAGE`**: the Trivy version to use. Default Trivy 0.74.0, fixed by its
  digest so it can't change without review. To move to a newer version after reviewing it,
  pull it, get its digest with
  `docker image inspect aquasec/trivy:<version> --format '{{index .RepoDigests 0}}'`, and
  set this to the result.
- **`SBOM_TRIVY_CACHE`**: the Docker volume holding Trivy's vulnerability database. Default
  `trivy-cache`.
- **`SBOM_SCAN_TIMEOUT`**: the longest one image's scan may take, as a number and a unit,
  for example `30m`, `90m` or `2h`. Default `30m`.
- **`SBOM_MIN_FREE_GB`**: disk space registry mode always leaves free on Docker's disk, in
  GB. Default 10. Before each download it checks there is room for about five times the
  image's download size on top of this, and skips the image if not. When the registry
  doesn't report a size, only this minimum is checked.


## When something goes wrong

Problems during a run show up in Wazuh as rule 100209 (some images failed) or 100210 (the
run couldn't scan at all), with the reason in `data.errors`. Images registry mode gave up on
in earlier runs are counted in every summary's `data.abandoned`. The scanner's own log has
the detail: `/var/log/sbom/registry.log` for registry mode, or
`journalctl -u sbom-scan.service` for host mode.

**"not enough disk space"**
Docker's disk doesn't have room for the image. Free some space (for example
`docker image prune`), or lower `SBOM_MIN_FREE_GB` if the 10 GB margin is more than this
machine needs. The image is tried again on the next run.

**"permission denied … Docker daemon socket"**
The scanner's user isn't in the `docker` group, or hasn't logged in again since being added
(installation step 2).

**"Cannot write the Wazuh log"**
`/var/log/sbom` is missing or owned by another user (installation step 6).

**"Cannot reach MongoDB"**
MongoDB isn't running or the address in `.env` is wrong. On the MongoDB machine, check
`docker ps` and `docker logs mongodb`.

**"rejected the scanner's login" or "token request refused"**
The registry login is missing, wrong or expired. Run `docker login <registry>` again as the
scanner's user.

**"scan failed … context deadline exceeded"**
The image took longer to scan than `SBOM_SCAN_TIMEOUT` allows (30 minutes unless changed).
Raise it in `.env`, for example `SBOM_SCAN_TIMEOUT=2h`. For host mode, also check that the
whole nightly run still fits in the time `deploy/sbom-scan.service` allows it
(`TimeoutStartSec=4h`); raise that too if not.

**"couldn't ask Docker about …"**
Docker didn't answer in time, often because it is busy, for example during a large build.
Nothing is downloaded or removed for that image, and it is tried again on the next run.

**"left … on this machine"** (rule 100209)
A downloaded image was scanned, but couldn't be removed afterwards: Docker didn't answer,
or refused because something is using the image. The message, also in the run summary's
`errors`, gives the command that removes it.

**"giving up on …"** (counted as `abandoned` in the run summary)
The image failed three runs in a row, so registry mode no longer tries it. The run where it
failed the third time raised rule 100209 and said why; after that, every run summary
counts it under `abandoned`. If the scan ran out of time, raising `SBOM_SCAN_TIMEOUT` gives
it three new tries automatically. After fixing anything else, such as a login, run
`python3 scan_registry.py --retry-failed` once. (After updating from an earlier version of
the scanner, images it had given up on get three new tries.)

**"not among this machine's images"**
Host mode was given an image, in an inventory file, that isn't on the machine. It only
scans images that are already there. Pull the image first, or scan it from its registry
with registry mode.

**"skipped, this machine has a different image under this name"** (with `--local`)
The machine has an image under a tag the registry also has, and Docker can't show it is the
registry's image: usually a build that hasn't been pushed yet, or an old download. The
machine's image is scanned (and reported under one of its names), and the registry's
version of that tag is skipped until the two match again, after a push or a pull. The run
summary counts these tags as `skipped`. This is a note, not a failure.

**Alerts are in the log file but not in the dashboard**
On the manager, run `sudo /var/ossec/bin/wazuh-logtest` and paste one line from
`/var/log/sbom/trivy-findings.jsonl`. It should match a rule between 100201 and 100210. If
it doesn't, the rules aren't installed (installation step 8). On the scanning machine, check
the agent with `grep -i sbom /var/ossec/logs/ossec.log`.

**"Agent event queue is full" alerts in Wazuh**
Lower `SBOM_WAZUH_EPS`, or raise `<client_buffer>` in the agent's configuration.

**Rule 592, "Log file size reduced"**
Something emptied the alert file. Rotate it only with the provided logrotate configuration,
which renames the file instead of emptying it. Never add `copytruncate` to it, and never
clear the file with `>`.

To see the latest alerts:
```bash
tail -n 3 /var/log/sbom/trivy-findings.jsonl | python3 -m json.tool --json-lines
```


## Known limitations

- **Conda packages are partly missed.** Trivy finds Conda packages only in named
  environments (`<conda>/envs/<name>/`), not in the base environment, and never matches
  vulnerabilities to them. Machine-learning images that install into `/opt/conda` can lose
  that layer. Packages installed with pip are covered.
- **Registry mode scans each image version once.** A vulnerability published afterwards is
  only reported when that version is rebuilt. Host mode re-scans every night and catches
  these, as does `--local` for the images on the machine.
- **Each version is reported separately.** A new version of an image is reported under its
  own name, such as `app:1.5.0`, so its first scan sends its full contents rather than only
  what changed since `app:1.4.2`.
- **With `--local`, a tag that differs** between the machine and the registry is scanned
  from the machine only, until the two match again. The run summary counts these as
  `skipped`.
- **One processor type per run.** Images are scanned for the platform set in
  `registries.json`, by default `linux/amd64`.
- **One scanner.** All results come from Trivy. No second scanner checks them.
- **Large images are slow.** A 10 GB image can take 20 minutes or more to download, and the
  first scan sends several thousand alerts.


## Security notes

- Trivy runs with access to Docker, which is equivalent to root access on the scanning
  machine. That is why the Trivy version is fixed by digest and only updated after review.
- The scanner's user is in the `docker` group, which is also equivalent to root. Use a
  dedicated account.
- `.env` can contain passwords. Keep it readable by the scanner's user only
  (`chmod 600 .env`). Git ignores it, so it is never committed.
- Use a read-only registry account. The scanner only ever pulls.
- The MongoDB started in installation step 5 has no password and only accepts connections
  from the same machine. Keep it that way, or add a password before opening it to the
  network.


## Files in this repository

- `scan_registry.py`: registry mode.
- `scan_all.py`: host mode, and the scanning and change-tracking code both modes use.
- `registries.example.json`: the template for `registries.json`, which says which registry
  registry mode scans.
- `.env.example`: the template for this machine's settings.
- `export_cyclonedx.py`: the combined SBOM described under
  [Running it by hand](#running-it-by-hand).
- `sbom_common.py`: settings and helpers shared by the scripts.
- `wazuh/sbom_rules.xml`: the alert rules for the Wazuh manager.
- `wazuh/agent_localfile_block.xml`: the Wazuh agent setting that reads the alert file.
- `deploy/`: the hourly and nightly schedules, and log rotation.
- `tests/`: automated tests.

**Running the tests:**
```bash
pip install -r requirements.txt
python3 -m pytest -q
```
They use sample Trivy output and an in-memory stand-in for MongoDB, so they need neither
Docker nor a database.
