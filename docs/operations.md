# Operating

How to bring over earlier signatures, roll the service out, and run it day to day. Setting it up
is in [deploy.md](deploy.md); how the data and the audit log work is in [design.md](design.md).

## Earlier contributors

People who contributed before the CLA existed can be treated as having signed. `seed` lists everyone with a commit on a default branch (`/contributors`) or a
pull request in any non-fork repo of the organization:

```bash
make build-tool
GITHUB_TOKEN=$(gh auth token) ./cla-tool seed -org <your-org> -o grandfathered.json
```

The token needs read access to the organization's repositories. Copy the file into the data
directory; the service logs it on its next refresh. Skip this step to make everyone sign.

## Coming from cla-assistant

Export its signatures while logged in to cla-assistant.io as an admin of the organization, from
the browser console on that site:

```js
const res = await fetch('/api/cla/getAll', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ org: '<your-org>', gist: { gist_url: '<the URL of your CLA gist>' } }),
})
copy(JSON.stringify(await res.json()))
```

- This is for a CLA linked to the whole organization. For one linked to a single repository,
  send `{ repo: '<repo>', owner: '<your-org>', gist: ... }` instead, once per linked repository.
- Use the organization's name (`org`), not its ID (`orgId`): after a rename, cla-assistant's
  lookup by ID can resolve to the old name and return nothing.

Save the clipboard to a file, then:

```bash
./cla-tool import -export export.json -recipient age1... -key-id 2026-01 -dir /srv/cla/data
./cla-tool verify -dir /srv/cla/data -identity cla-2026-01.key
```

- Each account keeps its earliest signature that was not revoked; revoked ones and entries
  without an account ID are skipped and counted. Records land in `signatures/` with
  `origin: cla-assistant`, and the name and email are sealed like any other signature.
- cla-assistant only knows the repository someone signed from, so `pr` stays empty, and an
  employer signature is imported as confirmed (`confirmed_by: cla-assistant import`), since it
  had no confirmation step.
- Run it on the host, or anywhere and copy the directory over before the first start. It can
  also run while the service does: it works in short locked batches, leaves accounts that
  already have a signed or pending record alone, and logs each record it writes. Running it
  again with a newer export only adds what is new.

Delete the export afterwards; it holds names and emails in plain text.

## Rollout

Replacing another CLA tool without a gap:

1. Seed the earlier contributors and import the old tool's signatures first (above): installed
   on an empty data directory, the App finds every author of every open pull request unsigned.
2. Install the App on one or a few repositories and run with `STATUS_CONTEXT=license/cla-next`
   and `PR_COMMENTS=false` next to the old tool, so both report, nothing is required yet, and
   only the old tool comments. Compare the two statuses on real pull requests for a while.
3. Take a final export from the old tool and import it.
4. Switch to `STATUS_CONTEXT=license/cla` and `PR_COMMENTS=true`, install the App on every repository, make the
   status required in branch protection (see [Security model](design.md#security-model)), then remove the old tool's
   webhook and link.

Starting fresh, without an earlier tool, only step 3 applies.

## Logs and alerts

The service logs JSON to stdout. Each request gets an access log line with the method, path
(never the query), status, duration and client address. The address is `X-Real-Ip` as the
proxy in front sets it (Traefik does by default), else the peer address. Health probes from
inside the container are not logged.

With `DISCORD_WEBHOOK_URL` set, these go to Discord. None carries personal data or error
text, only the problem, the repository and pull request where there is one, which GitHub call
failed (in words, such as "while setting the commit status") and GitHub's status code with its
name, for example `rotki#12 while setting the commit status (GitHub 502 Bad Gateway)`.

| Alert | When |
|---|---|
| GitHub refused the App an installation token | the App was uninstalled from the organization or the installation is suspended; nothing can be checked |
| The App has no access to a repository | GitHub answered 403 or 404 for a repository: the App is not installed there, or a permission is missing |
| CLA check failed | a pull request could not be checked or its status not posted, for any other reason |
| GitHub rate limit reached | a check or sweep hit a limit and was deferred |
| Reconcile sweep failed | the periodic search for open pull requests failed |
| Reading / writing the data directory failed | a refresh, the admin page or a signing could not use the volume |
| Webhook with an invalid signature rejected | a delivery failed the HMAC check |
| Backup failed or was skipped | an archive could not be written; it is retried |
| Backup written, but the data failed verification | the archive is kept with an `-unverified` suffix |
| The audit log chain is broken | the anchor check found the chain broken or the last published head missing |

Each problem sends one message at once; repeats within the hour are counted and summarised
once the hour is over, and a **Recovered** message follows when it clears. Some alerts clear
only once everything they covered recovered: a check failure, no access or a refused token
when no pull request is still failing, a rate limit when nothing is still waiting on one. A
pull request in a repository that leaves the installation (or `excluded_repos`) stops counting
at the next listing of the installation's repositories, since nothing re-checks it.

The audit anchor (`AUDIT_ANCHOR_INTERVAL`, default daily, only when the head moved) is an
`audit anchor` line in the log with the head's sequence number and hash, nothing else. With
`AUDIT_ANCHOR_DISCORD=true` it is posted to Discord as well.

## Maintenance

`cla-tool` is in the image, so the commands run inside the container against the live volume
(`docker compose exec cla /cla-tool verify -dir /data`), or on the host with `make build-tool`
against the volume's path. Commands that change records take the service's lock and log every
change. Run as root on the host, they first read what needs root (a private key, an export)
and then switch to the data directory's owner: they can then read and write only what the
service user may, so a symlink planted in the volume from inside the container cannot make
root overwrite or archive a host file, and everything they create belongs to the service. The
data directory must exist and must not be owned by root. Anything needing a private key
belongs on the host or an admin's machine, never in the container.

- **Check the records:** `cla-tool verify -dir /data [-identity <key>] [-anchor <seq>:<hash>]`.
  It checks that every record parses, matches its file name and has the fields the service
  relies on, that `config.json` and `grandfathered.json` are sound, that the audit log is an
  unbroken chain matching every file, and, given the private key, that every record decrypts.
  With an anchor (from a backup manifest kept off the host, or the Discord channel) it also checks that the log was not rebuilt since. It
  prints counts and problems, never names or emails. Run it after an import, after a rotation,
  and in the yearly restore test.
- **Records are never deleted.** The CLA grants a perpetual, irrevocable license, and a record
  is the proof of it, so there is no command to remove one. A request to delete a signer's data
  is a matter for the operator's privacy policy (records kept to establish or defend legal
  claims), not for this tool. Someone who no longer wants to contribute stops contributing.
- **Rotate the encryption key:**
  1. `age-keygen -o cla-2027-01.key` for the new pair; store it like the old one.
  2. `cla-tool rekey -dir /srv/cla/data -identity cla-2026-01.key -recipient age1<new> -key-id 2027-01 -dry-run`,
     then the same without `-dry-run`, on the host. It decrypts every record first and changes
     nothing if one fails, then rewrites them in batches while the service keeps running; a
     run that stopped halfway can be repeated. Each record gets a `rekeyed` event.
  3. Set `AGE_RECIPIENT` and `AGE_KEY_ID` to the new key and redeploy.
  4. Run the same `rekey` once more: it picks up the signatures made with the old key while the
     first run and the redeploy were under way, and skips everything else.
  5. `cla-tool verify -dir /srv/cla/data -identity cla-2027-01.key`.
  6. **Destroy the old private key** (password manager, paper copy) once every backup made
     before the rotation is gone: both off-site copies and the archives in `BACKUP_DIR`, which
     are replaced as the data changes. Until then, restoring one of them needs the old key.
  If the old key **leaked**, also delete the backups made before the rotation and treat those
  records as exposed. Only the name and email are ever encrypted; the other fields are
  plain text in the backups either way.
- **Read a record's personal data:**
  `cla-tool decrypt -identity cla-2026-01.key /srv/cla/data/signatures/<id>.json`
- **A material change to the CLA:** point `cla_revision` at the new gist revision. To make everyone
  sign again, stop the service and move `signatures/`, `pending/` and `audit/` together into an archive
  outside the data directory (say `archive-<old revision>/`, with a copy of `config.json`); it
  stays verifiable with `cla-tool verify -dir`. The service starts a new log. `grandfathered.json`
  covers earlier contributors only if you keep it.

## Backups

The data volume is the only copy, so it must be copied off the host. The work is split in two.

**The service writes a verified archive.** Every `BACKUP_INTERVAL` it takes the data lock, runs
the same checks as `cla-tool verify`, and, still holding the lock, writes the directory as a
plain tar into `BACKUP_DIR`. The archive is exactly the state that was checked, and no
signature can land halfway through it.

```
cla-20261027T020000Z.tar     the data directory, without the lock and temporary files
cla-20261027T020000Z.json    the manifest, written last: a finished archive has one
```

```json
{"time": "2026-10-27T02:00:00Z", "archive": "cla-20261027T020000Z.tar", "bytes": 1843200,
 "sha256": "4be1…", "ok": true, "problems": 0, "records": 1204, "grandfathered": 3311, "events": 1530, "head": "9f2c…"}
```

- **A failed check still writes the archive**, named `…-unverified.tar` with `"ok": false`, and
  alerts with the number of problems. The copy of the bad state is kept for investigation,
  next to the last verified one, which is never pushed out by unverified archives.
- **A backup that could not be written or was skipped** (the lock timed out, the directory is
  missing or full) alerts and is retried after 15 minutes. Alerts go to `DISCORD_WEBHOOK_URL`,
  at most once an hour per kind, with a recovery message once it works again.
- The first backup after a restart is due an interval after the newest archive already in the
  directory, so restarts do not add archives. Only the newest `BACKUP_KEEP` are kept, plus
  the newest verified one when newer unverified archives would push it out.
- **Archives are repeatable.** Entries are in name order and carry only names, sizes and
  contents, with fixed times, owners and modes, so unchanged data gives a byte-identical archive
  and the same `sha256`, whatever happened to the files' timestamps or permissions.
- `cla-tool backup -dir /data -o <dir>` does the same by hand and prints the manifest; it exits
  non-zero when the check failed.

**A backup job encrypts and ships it.** Anything that picks up finished archives (those with a
manifest), encrypts them and uploads them off the host will do; it mounts the backups volume
on the same node. That job should alert when an upload fails, when no new archive has appeared for longer than the interval plus
an hour (the service may have stopped without being able to alert), and when a manifest says
`"ok": false`.

The job need not upload an archive that did not change: upload only when the `sha256` differs
from the last *successful* upload, and otherwise log that it was unchanged, without an alert.
Comparing with the last successful upload, not the last archive seen, makes a failed upload
retry the next day.

The archives hold the sealed names and emails and the plain-text logins, companies and roles,
so they must be encrypted before they leave the host.

**Retention: the current copy and the one before it.** The live directory keeps the full
history, so off-site needs only recent states. Keep the two newest verified archives: when the
data changes, upload the new one, and delete the oldest only once that upload is confirmed, so
there are never fewer than two copies once two exist. A change that is valid but wrong, such as
a mistaken rejection or settings edit, can then still be undone from the copy before it, until
the next change replaces that one too. Two rules keep this safe:

- **An unverified archive never counts as one of the two.** Upload it next to them; it is
  removed once a newer verified archive lands, which leaves the two newest verified ones.
- **No age-based expiry** (such as a bucket lifecycle rule) on these archives: during a quiet
  stretch it would delete the only copies. With bucket versioning, expire *noncurrent* versions
  after a while, or replaced archives pile up.

## Restore

Decrypt and unpack into a scratch directory, run
`cla-tool verify -dir <restore> -identity <key> -anchor <latest anchor>`, then stop the service,
swap the directory in, and start it again. Test a restore once a year.
