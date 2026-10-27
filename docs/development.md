# Development

Go 1.27 or later; Docker with Buildx for the image checks; Node and pnpm only for commit-lint
and the release notes.

```bash
make test     # go test -race ./...
make test-cover  # the same with coverage, as a per-package table (CI posts it to the job summary)
make lint     # golangci-lint
make build
make preview  # serve the pages against a fake GitHub; any login becomes @newbie, an org admin
make check    # tests, lint, govulncheck, actionlint, zizmor, typos (CI also runs commit-lint and the image check)
scripts/check-image.sh  # build the image; check its context and contents
```

Tests run against `internal/fakegh`, an in-memory fake of the GitHub endpoints the service uses.

## CI

Every pull request and push to `main` runs commit-lint, typos, zizmor, golangci-lint, the tests
with the race detector and coverage (a per-package table in the job summary), govulncheck, and
builds the image with `scripts/check-image.sh`. That check asserts the exact contents of the
build context and the image (the two binaries, the CA bundle and the two data directories,
owned by `65532`). CodeQL scans the Go code and the workflows.

## Releases

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

- **Only from `main`.** A first job checks that the tagged commit is on `main` and stops the
  release otherwise, whoever pushed the tag.
- **Release notes** on GitHub, from the conventional commits since the previous tag.
- **The image** for `linux/amd64` and `linux/arm64`, pushed to Docker Hub as `rotki/cla:X.Y.Z`,
  `X.Y` and `X`, plus `latest` unless the tag is a pre-release such as `v1.3.0-rc.1`. The image
  check runs first, on the exact sources released, and nothing is pushed if it fails. No build
  cache is used, so nothing from an earlier run can end up in a release.
- **Provenance and an SBOM.** BuildKit attaches SLSA build provenance (sources, commit, build
  arguments, base image digests) and an SPDX software bill of materials (the Go modules, the Go
  version and the CA bundle) to the image. Both sit inside the image index, and the release
  then signs a provenance attestation for that index with Sigstore, through GitHub's artifact
  attestations, so the signature covers them too.
- **Repeatable.** Every file, layer and label time is the commit time, and the binaries are
  built with `-trimpath`, so the same commit gives the same image for each platform.

Checking a release:

```bash
# Built by this repository's release workflow, from the commit it names:
gh attestation verify oci://docker.io/rotki/cla:X.Y.Z -R rotki/cla

# What is inside it:
docker buildx imagetools inspect rotki/cla:X.Y.Z --format '{{json .SBOM}}'

# Rebuild it and compare (per platform; the index differs, since the
# provenance in it records when each build ran):
git checkout vX.Y.Z
epoch=$(git log -1 --format=%ct)
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --build-arg BUILD_DATE="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg VERSION=X.Y.Z --build-arg GIT_SHA="$(git rev-parse HEAD)" \
  --output type=oci,dest=cla.tar,rewrite-timestamp=true .
```

The `linux/amd64` manifest digest in `cla.tar`'s `index.json` must match the one
`docker buildx imagetools inspect rotki/cla:X.Y.Z` lists.

The Docker Hub credentials live in a protected GitHub **environment**, so only the release job
can read them. Set it up once, in the repository's Settings, Environments:

1. Create the environment `dockerhub`.
2. **Deployment branches and tags:** "Selected branches and tags", with the tag rule `v*` only.
   A branch, a pull request or another workflow cannot use it.
3. **Required reviewers** (recommended): one or two maintainers. The image job then waits for
   their approval; the release notes do not.
4. **Environment secret** `DOCKERHUB_TOKEN`: a Docker Hub access token with read and write
   access to `rotki/cla` only, from the account or organization that owns it.
5. **Environment variable** `DOCKERHUB_USERNAME`: the account the token belongs to.

Also protect the tags: a repository ruleset on `refs/tags/v*` that lets only maintainers create
them and nobody update or delete them, so a published version cannot be pointed elsewhere.
