# Releasing

`main` only accepts changes through pull requests that pass **Test & Check**, so the version bump goes through a PR.

1. Branch from `main` (e.g. `release/v0.9.7`) and run `cargo set-version --bump patch` (or `minor`/`major`; from `cargo-edit`).
2. Run `cargo check`, commit `Cargo.toml` and `Cargo.lock`, open a PR, and merge it once green.
3. Tag the merged commit and push the tag with your own credentials (tags pushed with `GITHUB_TOKEN` trigger no workflows):

   ```bash
   git switch main && git pull --ff-only
   grep '^version' Cargo.toml   # must match the tag
   git tag -a v0.9.7 -m "Release v0.9.7"
   git push origin v0.9.7
   ```

   If `main` has moved on, tag the PR's merge commit instead of `HEAD`.

The tag runs **Publish Release** (`.github/workflows/publish.yml`), whose three independent jobs publish:

- the crate to crates.io;
- `ghcr.io/obscura-messaging/obscura-server` tagged `X.Y.Z`, `X.Y` and `latest`;
- a GitHub release with generated notes.

If a job fails, fix the cause and rerun that job; never bump or retag. If the tag push started nothing, run **Publish Release** manually with the tag as the ref (the jobs skip on any non-tag ref).
