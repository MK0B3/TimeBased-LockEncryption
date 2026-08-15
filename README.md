# TimeBased-LockEncryption

[![CI](https://github.com/MK0B3/TimeBased-LockEncryption/actions/workflows/ci.yml/badge.svg)](https://github.com/MK0B3/TimeBased-LockEncryption/actions/workflows/ci.yml)
[![Go Reference](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A timelock encryption web app built in Go. Encrypt a message that cannot be decrypted until a chosen time has passed — not by the recipient, not by the server, not by you.

Uses [drand](https://drand.love/) randomness beacons and Identity-Based Encryption on the BLS12-381 curve. A message is encrypted to a *future drand round number* as its identity. That round's threshold signature does not exist yet and cannot be forged, so the ciphertext is undecryptable until the drand network publishes it — at which point the signature becomes the decryption key.

![The app: a message on the left, its ciphertext and the unlocked result on the right](docs/screenshot.jpg)

## Why there is no trusted server

The interesting property here is that the server never holds a key that could open a capsule early. There is no secret to leak and no admin override to abuse.

The unlock condition is enforced by a threshold signature from a distributed network of independent operators (the League of Entropy), not by a timer in this codebase. Anyone with the ciphertext can decrypt it the moment the round publishes, without this server's help.

## How it works

1. You write a message and choose a lock duration
2. The server converts that time into a future drand round number `r`
3. A random symmetric key encrypts the message; that key is sealed with IBE using `r` as the identity
4. When drand publishes round `r`, its BLS signature `σ_r` becomes the IBE private key for that identity, which unwraps the symmetric key
5. A background service polls for newly available rounds and decrypts capsules whose time has come

Step 3 is hybrid encryption, and it is why messages are not size-limited. Encrypting the message *directly* with IBE — the obvious approach, and what this project did initially — caps the plaintext at a single hash block of 32 bytes, which rejects any realistic message.

### Beacon verification

Every beacon fetched from the network is verified before it is used, in `pkg/beacon/client.go`:

```
e(σ, G2) == e(H(round), pubkey)
```

This is the standard BLS pairing check, run against the chain's public key using the scheme's RFC 9380 hash-to-curve and domain separation tag. Verifying here puts the check at the boundary where beacons enter the system rather than leaving it to each caller: `tlock` verifies again before unwrapping a ciphertext, but the client also feeds the beacon cache and the `/api/beacon/signature/:round` endpoint, which hands signatures to callers with no `tlock` involved.

The client implements `tlock.Network`, so decryption pulls its beacons through this verified path rather than reaching for the network directly. Signatures that are well-formed but bound to a different round are rejected — see `TestVerifyBeaconRejectsSignatureFromAnotherRound`, which uses a genuine signature from a neighbouring round, the case a length or well-formedness check cannot catch.

## Tech stack

- **Go** with [Gin](https://github.com/gin-gonic/gin)
- **drand** quicknet beacon network (unchained, 3s rounds)
- **[tlock](https://github.com/drand/tlock)** for timelock encryption
- **BLS12-381** pairing-based cryptography via [Kyber](https://github.com/drand/kyber)
- **BoltDB** for local capsule storage
- Vanilla HTML/CSS/JS frontend

## Project structure

```
cmd/server/main.go        # Entry point — web server and background decryption service
pkg/crypto/timelock.go    # Hybrid timelock encryption/decryption via tlock
pkg/beacon/client.go      # drand client: fetching, caching, BLS verification
pkg/api/handlers.go       # REST API handlers
pkg/storage/storage.go    # BoltDB persistence
web/                      # UI templates and static assets
```

## Run

### With Docker

No Go toolchain needed:

```bash
git clone https://github.com/MK0B3/TimeBased-LockEncryption.git
cd TimeBased-LockEncryption

docker compose up
```

Open **http://localhost:8080**. Capsules persist in a named volume across restarts; `docker compose down -v` discards them.

Or without compose:

```bash
docker build -t timelock-capsule .
docker run -p 8080:8080 -v capsules:/app/data timelock-capsule
```

### With Go

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/MK0B3/TimeBased-LockEncryption.git
cd TimeBased-LockEncryption

cp .env.example .env      # optional — defaults work as-is
go run ./cmd/server
```

Open **http://localhost:8080**. Or with make: `make run`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | Server port |
| `SERVER_HOST` | `localhost` | Server host |
| `DB_PATH` | `./data/capsules.db` | BoltDB file path |
| `DRAND_URLS` | `https://api.drand.sh,https://drand.cloudflare.com` | drand API endpoints |
| `DRAND_CHAIN_HASH` | quicknet | drand chain to use |
| `DECRYPT_CHECK_INTERVAL` | `30s` | How often to check for decryptable capsules |

> **Note on chain selection:** timelock encryption requires an **unchained** drand network, because the identity must be derivable before the signature exists. The default is quicknet (`52db9ba7…`). Pointing `DRAND_CHAIN_HASH` at the original League of Entropy chain (`8990e7a9…`) will not work — it is chained, and `tlock` rejects it.

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/capsules` | Create a time-locked capsule |
| `GET` | `/api/capsules` | List capsules (optional `?status=`) |
| `GET` | `/api/capsules/:id` | Get a capsule |
| `DELETE` | `/api/capsules/:id` | Delete a capsule |
| `POST` | `/api/decrypt` | Decrypt a capsule, if its round has published |
| `GET` | `/api/beacon/info` | Current drand beacon info |
| `GET` | `/api/beacon/signature/:round` | Beacon signature for a round |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/stats` | Capsule statistics |

Create a capsule that unlocks in one minute:

```bash
curl -X POST http://localhost:8080/api/capsules \
  -H 'Content-Type: application/json' \
  -d "{\"message\":\"hello from the past\",\"unlock_time\":\"$(date -u -d '+1 minute' +%Y-%m-%dT%H:%M:%SZ)\"}"
```

## Tests

```bash
go test -short ./...   # offline: API, storage, handler logic
go test ./...          # full suite, including live drand verification
```

The full suite reaches the real drand network to verify encryption round-trips and beacon signature validation. Network-dependent tests skip under `-short`, so CI stays deterministic.

## Limitations

- Capsules are stored in a local BoltDB file; there is no clustering or replication
- No authentication — anyone with access to the server can list and delete capsules
- Decrypted plaintext is written back to the database once a capsule unlocks
- Messages are capped at 64 KB, an arbitrary sanity bound rather than a cryptographic one

## License

MIT — see [LICENSE](LICENSE).
