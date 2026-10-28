# rotki CLA

Contributor License Agreement checks and signing for the rotki GitHub organization, replacing
cla-assistant.io. One GitHub App, one small Go service at `cla.rotki.com`, and a data directory on
a mounted volume that holds the signatures and a tamper-evident log of every change to them.

Any organization can run its own copy; set the `site` block in `config.json` so the pages and
footer name you instead of the defaults (rotki's source link and Rotki Solutions GmbH). See
[docs/deploy.md](docs/deploy.md).

## How it works

- **Checks.** On every pull request the App collects the commit authors (the committer when the
  author's email is not linked to an account), skips the allowlist and the exempt team, and
  sets the commit status `license/cla`. One bot comment per pull request lists who still needs to
  sign, linking their profiles without @mentions, and is edited in place (`PR_COMMENTS=false`
  turns it off). Merge queue commits pass straight away, since each pull request was
  checked before it entered the queue.
- **Signing.** The comment links to `/sign`, which shows the agreement with a GitHub login at its
  end. After logging in, the contributor gives their name, picks one of their verified emails,
  says whether they sign for themselves or their employer, and agrees. The check turns green
  within seconds.
- **Employer signatures** wait in `pending/` until an org admin confirms them on `/admin`. The
  page is not linked from the others; admins open it directly, and GitHub is asked whether they
  are an admin on every visit.
- **Manual re-check.** `/admin` also has a "Re-check all open pull requests" button for org
  admins, limited to once every 10 minutes for the whole service. It re-evaluates every open
  pull request, green ones included, but writes only where a result actually changed. Checks
  someone is waiting on (a webhook, a signing) always go first: the re-check and the 30-minute
  reconcile sweep queue behind them.
- **Reconcile.** Every 30 minutes the service re-checks open pull requests without a successful
  status, so a lost webhook or a restart only delays a check.
- **Storage.** Signatures live in a data directory on a mounted volume, never on GitHub, next to
  an append-only, hash-chained log of every change. Names and emails are encrypted to a key the
  service does not hold. A verified archive is written daily for a backup job to ship off the
  host. See [docs/design.md](docs/design.md).
- **GitHub quota.** Public pages never wait on GitHub, writes are paced well under GitHub's
  limits, and a rate limit is never waited out inside a request. See
  [docs/design.md](docs/design.md#github-quota).

## Try it

```bash
make preview
```

serves the real pages against a fake GitHub: any login becomes `@newbie`, an org admin. It prints
the address, the data directory (to look at the records and the audit log it writes) and every
commit status and bot comment it posts. Go 1.27 or later is needed.

## Documentation

- [Deploying](docs/deploy.md): the data directory, the age key, the GitHub App, configuration,
  running it, Traefik, Kubernetes, and stopping and updates.
- [Operating](docs/operations.md): earlier contributors and cla-assistant imports, the rollout,
  maintenance with `cla-tool`, backups and restore.
- [Design](docs/design.md): the data directory format, the audit log, GitHub quota handling and
  the security model.
- [Development](docs/development.md): building, testing, CI and releases.
- Examples: [`config.json`](examples/config.json), [`compose.yml`](examples/compose.yml) (Swarm
  and Traefik), [`kubernetes.yaml`](examples/kubernetes.yaml), [`logo.svg`](examples/logo.svg).

## License

[AGPL-3.0-or-later](LICENSE.md), Copyright (C) 2026 Rotki Solutions GmbH. Anyone running a
modified copy as a network service must offer its source to the people using it; point
`site.source` in `config.json` at it, and the page footers link there.
