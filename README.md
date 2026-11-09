# wacli-reader

Read-only HTTP query wrapper around checksum-pinned wacli v0.26.0. No send, mark-read, delete, archive, logout or other chat-management endpoints.

## Required environment

- READER_TOKEN: at least32 characters, stored as a secret.
- EXPECTED_PHONE: authorized account digits including country code. Every query and sync checks typed local auth status against this account. A mismatched account is never exposed or synced further.
- AUTH_HISTORY_DAYS and AUTH_HISTORY_MAX_PER_CHAT: positive values, explicitly chosen by account owner, required only to initiate pairing. Max30 days/1000 messages per chat. The phone may ignore requested pairing history limits and send more.
- Optional PORT (10000), WACLI_STORE_DIR (/tmp/wacli-store), WACLI_BIN.

Only /health is public. All other routes require Authorization: Bearer token and return no-store headers.
GET /status returns typed flags only. GET /chats, /messages, /search require a verified account and invoke wacli --read-only with fixed argument lists. Limits1-200. Search accepts q, optional chat/after/before filters. Dates YYYY-MM-DD.
POST /auth/start initiates QR pairing with explicit history settings, expires after180s. GET /auth/output contains only a typed state and transient QR while pairing is running, never raw bootstrap output. QR is cleared at process completion. Auth necessarily imports phone-provided bootstrap history. If a different account is scanned, the data stays blocked; operator must stop and arrange owner-controlled remediation.
POST /sync is permitted only when account matches. It performs one quiet sync, stops after10s idle or90s total, max10000 messages/200MB local storage. No continuous sync, startup sync, daemon reconnect loop, cron or keepalive configured. Do not call sync without an owner request.

## Render Free limits

Filesystem is ephemeral and local session can be lost on spin-down, restart or redeploy. There is no durable-session guarantee. No keepalive policy approval has been established. Never add billing or a paid instance without owner permission. Use a non-root container. Never store session databases, QR payloads, secrets or message bodies in git, public logs or health responses.

## QA

`go test -race ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...`.
Fake executable tests validate security logic only, not real WhatsApp protocol behavior. Live pairing/account verification and a real read remain separate gates.
