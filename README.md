# TimeBased-LockEncryption

A timelock encryption web app built in Go. Encrypt messages that can only be decrypted after a chosen time has passed — no one (not even the server) can unlock them early.

Uses [drand](https://drand.love/) randomness beacons and Identity-Based Encryption (IBE) on the BLS12-381 curve. The encryption is tied to a future drand round number, and decryption is only possible once that round's beacon signature is published.

## How It Works

1. You type a message and choose a lock duration (e.g. 3 seconds, 1 hour, 1 day)
2. The server calculates which future drand beacon round corresponds to that time
3. Your message is encrypted using IBE with that round number as the identity
4. When the drand network publishes that round's signature, the message becomes decryptable
5. A background service automatically checks for and decrypts unlocked capsules

## Tech Stack

- **Go** with [Gin](https://github.com/gin-gonic/gin) web framework
- **drand** beacon network for verifiable randomness
- **tlock** library for timelock encryption
- **BLS12-381** pairing-based cryptography via Kyber
- **BoltDB** for local capsule storage
- HTML/CSS/JS frontend

## Project Structure

```
cmd/server/main.go        # Entry point — starts the web server and decryption service
pkg/crypto/ibe.go         # IBE encryption/decryption using tlock + drand
pkg/crypto/timelock.go    # AES-GCM timelock encrypt/decrypt
pkg/beacon/client.go      # drand beacon client with caching and verification
pkg/api/handlers.go       # REST API handlers (create, list, decrypt capsules)
pkg/storage/storage.go    # BoltDB storage layer
web/templates/index.html  # Web UI
web/static/               # CSS and JavaScript
```

## Prerequisites

- [Go 1.22+](https://go.dev/dl/)

## Run

```bash
# Clone the repo
git clone https://github.com/MK0B3/TimeBased-LockEncryption.git
cd TimeBased-LockEncryption

# (Optional) Copy and edit environment config
cp .env.example .env

# Start the server
go run cmd/server/main.go
```

Open **http://localhost:8080** in your browser.

## Configuration

Environment variables (set in `.env` or export directly):

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | Server port |
| `SERVER_HOST` | `localhost` | Server host |
| `DB_PATH` | `./data/capsules.db` | SQLite database path |
| `DRAND_URLS` | `https://api.drand.sh,...` | drand API endpoints |
| `DRAND_CHAIN_HASH` | quicknet hash | drand chain to use |
| `DECRYPT_CHECK_INTERVAL` | `30s` | How often to check for decryptable capsules |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/capsules` | Create a new time-locked capsule |
| `GET` | `/api/capsules` | List all capsules |
| `GET` | `/api/capsules/:id` | Get a specific capsule |
| `DELETE` | `/api/capsules/:id` | Delete a capsule |
| `POST` | `/api/decrypt` | Decrypt a capsule (if round is available) |
| `GET` | `/api/beacon/info` | Get current drand beacon info |
| `GET` | `/api/beacon/signature/:round` | Get beacon signature for a round |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/stats` | Capsule statistics |

## Tests

```bash
go test ./...
```
