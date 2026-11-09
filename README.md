# wacli-reader

Small read-only HTTP wrapper around the official `wacli` release (checksum-pinned in the Dockerfile).
Bearer token from the `READER_TOKEN` env var protects every route except `/health`.
No send routes. Queries run `wacli --read-only`; only `sync` and `auth` write, to the local store.
