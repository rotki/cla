# Design

How the service keeps its data, proves nothing was changed behind its back, stays within
GitHub's limits, and what it protects against. [deploy.md](deploy.md) and
[operations.md](operations.md) say what to do; this explains why.

## The data directory

All state lives in one directory (`DATA_DIR`, `/data` in the image), meant to be a mounted volume
that is backed up:

```
config.json            pinned CLA revision, allowlist, exempt team, excluded repos, branding
logo.svg               optional header logo (or logo.png)
grandfathered.json     account IDs treated as signed (earlier contributors)
signatures/<id>.json   signed
pending/<id>.json      employer signature awaiting an admin
audit/events.jsonl     the audit log
journal.json           a change in progress; present only while one runs, or after a crash
```

A record stores the GitHub ID, login, date, CLA revision, category, the pull request, and for
employers the company and role, in plain text. The signer's name and email are encrypted with age to
a public key; the service cannot decrypt them. No IP address, browser details or GitHub token is
stored. Writes go through a synced temporary file and a rename, so a crash never leaves half a
record.

A record changes before its audit event is appended, so a crash in between could leave a
signature no event accounts for. Each change therefore first writes `journal.json` with the
earlier contents of the files it touches and the log's length. Whoever takes the lock next (the
service at startup and before each write, `cla-tool` before each batch, the backup) puts back
every file whose event never landed and removes the journal; a change whose event did land is
kept. `cla-tool verify` only reports a journal it finds.

## The audit log

Every change appends one JSON line to `audit/events.jsonl`: signed, pending, confirmed, rejected,
rekeyed, imported, and changes to `config.json` or `grandfathered.json` (including hand
edits, logged on the next refresh). A line holds the time, the action, the actor (`signer`,
`admin:<login>`, `service` or `cla-tool`), the SHA-256 of the file as it stands afterwards, and the
hash of the line before it.

- **Tamper-evident.** Editing, removing or reordering a line breaks every hash after it, and
  `cla-tool verify` checks that each record is exactly what its last event says, that no record
  vanished without an event, and that the settings files match. The service refuses to write
  while the chain is broken. It checks the whole chain on its first write and only what was
  appended since on later ones; the daily backup checks it all again.
- **Survives a torn write.** A write cut short by a full disk or a power loss leaves a partial
  last line. It is skipped, the next event starts on a line of its own, and `verify` reports
  the fragment as a note, not a problem: no event is lost from the chain, and the log never has
  to be edited. A record whose event could not be written is removed again, so the service
  never counts a signature the log does not show.
- **No personal data.** Events name an account by a pseudonym: an HMAC of its ID under a random
  salt stored only in its record, so the log can be anchored and backed up without saying who
  signed. An account's events are dated to the day only, since a signing re-checks a public pull
  request at once and an exact time would match it.
- **Anchored outside the server.** Someone with root on the host could rebuild the whole chain.
  So at start and every `AUDIT_ANCHOR_INTERVAL` (24 h) the service logs the newest sequence
  number and hash when it moved. It checks the whole chain first and alerts instead when it is
  broken. The log stays on the host, so with `AUDIT_ANCHOR_DISCORD=true` the anchor is also
  posted to the Discord alert channel; it then counts as published only once Discord accepted
  it, and a failed post is retried after 15 minutes. That is off by default, since an active
  log means a message a day. Each backup manifest's
  `head`, shipped off the host daily, is a second anchor. `cla-tool verify -anchor
  <seq>:<hash>` checks the log against any of them; a rewritten log fails it. The service
  itself also checks, before each anchor, that the log still holds the head it last published
  (after a restart, the one in the newest backup manifest), and alerts instead if it was cut
  back or rewritten. Events after the newest anchor are not covered until the next one.
- **Append-only on disk.** The log is never rewritten, so the host can enforce it:
  `chattr +a <volume>/audit/events.jsonl` (root only, also blocks root's own accidental edits).
- **Writers take one lock** (`.lock` in the directory, `flock`), shared by the service and
  `cla-tool`, so maintenance can run while the service does. The service waits at most 20
  seconds for it, counted once across its own lock and the file lock, and then fails, so a
  stuck holder shows up as an error page and an alert rather than as a request that hangs.
  Long jobs (`import`, `rekey`) work in batches of 100 records and let go in between, so
  signing carries on meanwhile.

## GitHub quota

cla-assistant's public pages hung for minutes when its shared token ran out and its client
waited for the reset. Here:

- Visitor-facing pages (`/`, `/cla`, a logged-out `/sign`) never wait on GitHub: the CLA is
  rendered once per revision and served from memory, and a page that finds it missing only
  starts a background load. Signatures are read from disk and cost no quota.
- Every call has a 10 s timeout. A rate limit is never waited out inside a request: the job
  is rescheduled and one throttled alert goes out.
- After a secondary limit no call at all goes out until `Retry-After` (or a minute) has
  passed, and a spent quota blocks its resource until the reset, since GitHub warns that
  requests sent while limited can get an integration banned. Repeated limits back off
  exponentially (1 min doubling to 1 h, six tries, then the next sweep). GraphQL limits are
  recognised from the error type, the message or the headers, since they arrive with a 200.
- Background work (the sweep and the jobs it queues) pauses below 10% of the quota.
- Writes go out one at a time, a second apart, and at most 400 an hour, under GitHub's
  content-creation limit of about 500 that people in the org share. 50 of them are kept for
  the re-checks after a signing or an admin's decision, so pushes cannot use up what a signer
  waits on.
- A pull request already checked at its head commit, with the same signatures and exempt
  team, is skipped without a single write. `/ready` shows the remaining quota and the queue
  depth.

## Security model

- **Require the status from this App.** In each repo's branch protection or ruleset, require
  `license/cla` with this App as the expected source. Otherwise any integration or workflow with
  `statuses: write` could post a green status under the same name.
- **Bots.** A git name or email is free text, so a commit only counts as a bot's when the pull
  request itself was opened by a GitHub bot account (which GitHub authenticates). In a pull
  request opened by a person, a commit named `something[bot]` must be linked like any other.
  That holds for commits linked to a bot account too (renovate's are): GitHub links a commit
  by its email, and anyone can use a bot's noreply address.
- **Commit attribution** comes from the commit email, as in cla-assistant: anyone can author a
  commit with someone else's public email, and GitHub then shows it as theirs. Review the commits
  of pull requests from unknown contributors as usual.
- **Webhook bodies** are capped at 1 MB before the signature check. GitHub documents only its own
  25 MB cap; a `pull_request` delivery is typically tens of kilobytes (about 28 KB on a busy
  repository we measured).
- **Sessions** live in a cookie encrypted and authenticated with AES-256-GCM under a key
  derived from `SESSION_KEY`, so a stolen cookie reveals neither the name nor the verified
  emails in it. It expires after 15 minutes. Over HTTPS the cookies carry the `__Host-`
  prefix, so the browser takes them only from this exact host and no other subdomain can plant
  one. Admin rights are never stored in the session: GitHub is asked again after a minute, so a
  removed admin loses access within that minute. A "no" is kept for ten minutes, so any
  logged-in account looping on `/admin` costs one API call per ten minutes; logging in again
  drops the cached answer, so a new admin need not wait.
- **Data directory permissions.** The records hold plain-text logins, companies and roles, and
  sealed names and emails. Keep the volume readable by the service user and the host's admins
  only.
- **Logs** are one JSON object per line on stdout, in a shape Loki and Grafana read directly:
  lower-case `level`, RFC 3339 `time`, `message` and `service: cla`. They carry GitHub IDs and pull request numbers, never names, emails, tokens or webhook URLs.
- **The image and its supply chain.** The image is `scratch` with two static binaries, runs as
  `65532`, and is checked file by file in CI. It can run with a read-only root filesystem and no
  capabilities ([deploy.md](deploy.md#5-run)). Releases come only from version tags on `main`,
  carry signed build provenance and an SBOM, and can be rebuilt byte for byte
  ([development.md](development.md#releases)).
- **cla-tool as root** switches to the data directory's owner before touching it, so a symlink
  planted in the volume cannot make root write or read a file elsewhere on the host
  ([operations.md](operations.md#maintenance)).
