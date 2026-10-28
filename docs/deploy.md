# Deploying

One instance serves one GitHub organization. The steps below set it up; then
[operations.md](operations.md) covers bringing over earlier signatures, the rollout, and running
it day to day.

## 1. The data directory

Create a volume and put `config.json` (see [`examples/config.json`](../examples/config.json)) and
`grandfathered.json` (`[]` to start) in it. The image runs as `65532:65532` and ships `/data`
owned by that user, so a new named volume mounted there is writable as is. A bind mount must be
owned by it:

```bash
install -d -o 65532 -g 65532 -m 750 /srv/cla/data
install -o 65532 -g 65532 -m 640 examples/config.json /srv/cla/data/config.json
install -o 65532 -g 65532 -m 640 examples/logo.svg /srv/cla/data/logo.svg   # optional
```

Only the host's admins should be able to read it; it is backed up as described under
[Backups](operations.md#backups).

## 2. The age key pair

```bash
age-keygen -o cla-2026-01.key
```

The printed public key (`age1...`) goes into `AGE_RECIPIENT`, with `AGE_KEY_ID=2026-01`. Store the
key file in the company password manager and keep an offline copy. Without it the records cannot be
opened.

## 3. The GitHub App

Create an App owned by the org, installable on this account only. Replace `cla.example.org`
here and below with the host the service runs on.

| Setting | Value |
|---|---|
| Callback URL | `https://cla.example.org/oauth/callback` |
| Request user authorization during installation | off |
| Webhook URL | `https://cla.example.org/webhook`, with a secret |
| Repository permissions | Commit statuses: read & write · Pull requests: read & write · Contents: read · Merge queues: read · Metadata: read |
| Organization permissions | Members: read |
| Account permissions | Email addresses: read |
| Events | Pull request · Merge group (GitHub offers it only with Merge queues: read) |
| Logo | rotki's is [`examples/app-icon.png`](../examples/app-icon.png) (source: `app-icon.svg`); GitHub shows it at about 20 px next to the status |

Install it on all repositories, or the ones that take outside contributions. The App cannot
write to any repository's contents: signatures live on the server, not on GitHub.
`excluded_repos` are never checked. Generate a private key and a client secret.

## 4. Configuration

Two places hold the configuration: the environment, for the service itself, and `config.json`
in the data directory, for what maintainers change at runtime.

### Environment

Every secret (marked 🔒) can be given as an environment variable or, preferably, as a file: set
`NAME_FILE` to its path, such as a Docker/Swarm secret mounted at `/run/secrets/<name>`. Files
keep secrets out of the service spec and `docker inspect`. Setting both `NAME` and `NAME_FILE`
is a startup error, and a trailing newline in the file is ignored.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `BASE_URL` | yes | | `https://cla.example.org` |
| `GITHUB_APP_ID` | yes | | |
| `GITHUB_APP_CLIENT_ID` | yes | | for the user login |
| 🔒 `GITHUB_APP_CLIENT_SECRET` | yes | | |
| 🔒 `GITHUB_APP_PRIVATE_KEY` | yes | | PEM |
| 🔒 `GITHUB_WEBHOOK_SECRET` | yes | | |
| 🔒 `SESSION_KEY` | yes | | at least 32 bytes, e.g. `openssl rand -base64 48` |
| `AGE_RECIPIENT`, `AGE_KEY_ID` | yes | | public key and its name |
| `GITHUB_ORG` | yes | | the organization the App is installed on |
| `DATA_DIR` | | `/data` | the data directory; mount a volume here |
| `AUDIT_ANCHOR_INTERVAL` | | `24h` | how often the audit head is logged as an anchor, when it moved |
| `AUDIT_ANCHOR_DISCORD` | | `false` | `true` also posts each anchor to `DISCORD_WEBHOOK_URL` (required then). Set this or `BACKUP_DIR` (with the archives shipped off the host), or the anchor never leaves the host and the service warns at startup; see [design.md](design.md) |
| `BACKUP_DIR` | | | where verified archives are dropped for the backup job, e.g. `/backups`; empty turns backups off |
| `BACKUP_INTERVAL` | | `24h` | at least `1h` |
| `BACKUP_KEEP` | | `2` | archives kept in `BACKUP_DIR`; older ones are removed |
| `STATUS_CONTEXT` | | `license/cla` | `license/cla-next` during the shadow phase |
| `PR_COMMENTS` | | `true` | `false` during the shadow phase: only the status reports, no bot comment |
| 🔒 `DISCORD_WEBHOOK_URL` | | | alerts; no personal data, at most one message per problem per hour |
| `RECONCILE_INTERVAL` | | `30m` | at least `1m` |
| `WORKERS` | | `4` | |
| `PORT` | | `4000` | |
| `LOG_LEVEL` | | `INFO` | `DEBUG` for more, `WARN` drops the access log |

### config.json

`config.json` in the data directory is edited in place and picked up within a sweep (and
logged), with no redeploy. See [`examples/config.json`](../examples/config.json).

| Key | Meaning |
|---|---|
| `cla_gist`, `cla_revision` | the CLA text: a public gist and the revision to show and record |
| `allowlist` | logins that never need to sign; a bot account (`pre-commit-ci[bot]`) here is trusted in pull requests people open too |
| `exempt_team` | slug of a team whose members need not sign |
| `excluded_repos` | repos that are never checked |
| `site.name` | the name on the pages (default: the GitHub org name) |
| `site.legal_name` | the footer copyright holder (default: Rotki Solutions GmbH, the service's author) |
| `site.homepage` | the footer link (omitted if empty) |
| `site.source` | link to this service's source; **if you run a modified copy, the AGPL requires pointing it at your source** |
| `site.accent_color` | `#rrggbb` for buttons, links and highlights (light and dark shades are derived) |

Invalid values fall back to the defaults: a URL must be absolute `http(s)`, a colour must be
`#rrggbb`. Page templates and translations are not configurable.

### Logo

Optional: put `logo.svg` (or `logo.png`) in the data directory and the header
shows it instead of the coloured letter; it is picked up within a sweep. The service serves
it itself, so no visitor's browser fetches anything from another site. It may be at most
256 KB, and a symlink is ignored. An SVG is only ever shown through an `img` tag, where
scripts do not run, and is served with a policy that forbids them if opened directly. rotki's
is in [`examples/logo.svg`](../examples/logo.svg).

## 5. Run

The image is `rotki/cla` on Docker Hub, for `linux/amd64` and `linux/arm64` (see [Releases](development.md#releases)), built from the
`Dockerfile`: `scratch`, port 4000, `/server healthcheck`, about 18 MB.

**Run exactly one replica**, with the data directory on a local volume. The job queue, the
remembered results and the re-check limit live in memory; two replicas would sweep twice and
double the GitHub traffic. The lock is `flock`, which network filesystems such as NFS may not
honour, so keep the volume local to the node and pin the service to it in Swarm.

Hardening that the image cannot carry itself belongs in the service definition. The root
filesystem can be read-only and every Linux capability dropped: the service writes nothing
outside `/data` and `/backups` and never needs a privilege. `no-new-privileges` (not available
in Swarm) adds little here, since a `scratch` image running as a non-root user has no setuid
binary to gain privileges through. Pin the image by digest, so a moved tag cannot change what
runs. [`examples/compose.yml`](../examples/compose.yml) puts all of this together.

**Resources.** Measured with the pages under load (5,000 signing-page requests, 100 at a time,
fake GitHub included), the process stayed at about 26 MB resident. Suggested:

| | Limit | Reservation |
|---|---|---|
| Memory | 128 MB | 64 MB |
| CPU | 0.5 | 0.1 |

The service reads its container memory limit at startup and sets Go's soft limit (`GOMEMLIMIT`)
to 90% of it, so the garbage collector works harder as memory fills instead of the container
being killed; an explicit `GOMEMLIMIT` takes precedence. Go sizes its CPU parallelism from the CPU
limit on its own. Both show in the `runtime limits` log line at startup.

## Behind Traefik

[`examples/compose.yml`](../examples/compose.yml) carries a full set of Traefik labels for a
Swarm service, with the reasons in comments. Replace `cla.example.org`, the `le` certificate
resolver and the `public` network. They have not been tried against a live Traefik yet. In
short:

- **Shared protections:** a canonical `Host` header, a site-wide cap on requests in flight, and a
  per-client one (IPv6 grouped per /64).
- **Pages:** 60 requests a minute per client.
- **Login, logout, admin and `POST /sign`:** 10 a minute per client.
- **`/oauth/callback`:** also capped site-wide at 20 a minute, since only it spends one of
  GitHub's roughly 2,000 OAuth token requests an hour.
- **`POST /webhook`:** no per-client limit, since GitHub sends bursts from a few addresses; a
  site-wide cap and a 1 MB body limit instead.

Notes:

- **Client addresses.** `ipStrategy.depth: 0` uses the address Traefik sees. If a CDN or another
  proxy sits in front, every client looks like that proxy; set `depth` (or `excludedIPs`) so
  the per-client limits key on the real client, or they turn into site-wide ones.
- **Headers.** The service sets its own Content-Security-Policy, HSTS (when `BASE_URL` is
  https), `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy`. A shared
  security-headers middleware can be added, but if it also sets a CSP, browsers enforce both.
- **Forwarded headers.** The service never reads `X-Forwarded-*` or the client address, so no
  trusted-proxy setup is needed; TLS ends at Traefik and the service listens on plain HTTP.
- **Layers.** The service has its own limits too: signing 5 attempts per 10 minutes per
  account, the admin re-check once per 10 minutes, the 1 MB webhook cap, and the GitHub write
  budget. The proxy limits keep floods from reaching it at all.
- **Optional:** restrict `cla-webhook` to GitHub's hook addresses with an `ipallowlist`
  middleware fed from `GET https://api.github.com/meta` (`hooks`). GitHub changes them now and
  then, so the list needs refreshing; the HMAC check already rejects anything else.
- **Plain Docker** (no Swarm): put the labels on the container itself, use
  `traefik.docker.network` instead of `traefik.swarm.network`, and run it with
  `--memory 128m --cpus 0.5 --read-only --cap-drop ALL --security-opt no-new-privileges`.
- **Existing middlewares:** if your Traefik already has shared security-header or compression
  middlewares, use them in place of `cla-compress`.

## On Kubernetes

The same rules hold: one replica, the data on a volume only that pod mounts, secrets as files,
a read-only root filesystem with no capabilities, and time to stop gracefully.
[`examples/kubernetes.yaml`](../examples/kubernetes.yaml) is a sketch, not tried against a live
cluster: a Deployment with `strategy: Recreate` (one copy at a time, like Swarm's stop-first),
a 30-second termination grace period, the non-root user, a read-only root filesystem, no
capabilities or service account token, secrets mounted as files, probes, and two volume claims.

- **Volumes.** Use `ReadWriteOnce` claims on block or local storage. The lock is `flock`,
  which network-backed storage classes such as NFS may not honour. `fsGroup` makes a new
  volume writable by the service user.
- **The backup job** must mount `cla-backups` too. With a `ReadWriteOnce` claim the simplest
  way is a second container in the same pod; a separate `CronJob` would have to land on the
  same node.
- **Probes.** `/ready` answers 503 only until the signatures are loaded, never because of
  GitHub's quota, so the pod is not taken out of service while it waits for a reset.
- **Ingress.** Carry over the limits from the Traefik section with your controller's own
  settings: a per-client limit on pages, a stricter one on `/login`, `/logout`, `/admin` and
  `POST /sign`, a site-wide cap only on `/oauth/callback`, no per-client limit on
  `POST /webhook`, and a 1 MB request body cap. Most controllers need a separate Ingress per
  group of paths for this.
- **NetworkPolicy**, if your cluster enforces them: ingress only from the ingress controller,
  egress only to DNS, `api.github.com`, `github.com` and `discord.com`.

## Stopping and updates

On `SIGTERM` the service stops in this order, within about 25 seconds:

1. It stops accepting connections and lets requests in flight finish, up to 20 seconds, so a
   signing being saved completes.
2. Workers take no new checks; a check in progress gets up to 10 seconds to finish. Checks
   still waiting are dropped on purpose: the queue holds only what to re-check, and the sweep
   that runs right after the next start queues every open pull request without a green
   status again, including those whose webhook arrived while the service was down (GitHub does
   not retry failed deliveries by itself).
3. A backup in progress runs to its end.
4. Alerts still queued for Discord are sent, for up to 5 seconds.

Give it `stop_grace_period: 30s`: Swarm's default of 10 seconds can kill it in the middle of
this. Keep `update_config.order: stop-first`, Swarm's default: with `start-first` two copies run
for a few seconds, and while the data stays safe behind the lock, both could post the same bot
comment.

Stop-first does mean a short outage on every restart or update: from the moment the old copy
stops taking connections until the new one passes its first health check, usually a few
seconds (the image checks every 2 s while starting). In that window the pages answer with an
error and GitHub's webhook deliveries fail; GitHub records them as failed and does not retry.
Nothing is lost: statuses already on pull requests stay, so merges are not blocked, and the
sweep that runs as soon as the new copy is up re-checks every open pull request without a
green status. On Kubernetes, `strategy: Recreate` behaves the same way.
