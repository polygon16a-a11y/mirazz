# Relay Messenger

A small PeerJS chat with account registration and sign-in. Accounts are stored in SQLite; passwords are stored as salted scrypt hashes, and sign-in sessions use opaque, HTTP-only cookies.

## Repository notes

CI runs the test suite and dependency audit on Node.js 24. No license has been selected for this project yet. Before making the repository public, add the license you intend; without a license, GitHub visibility does not grant others permission to reuse the code.

## Requirements

- Node.js 22.5 or newer (uses the built-in `node:sqlite` module)
- A PeerServer signaling endpoint reachable by both browsers (the default PeerJS public service can be used for development)

Install locked dependencies with `npm.cmd ci` before running locally. The PeerJS browser client is served locally by the app; peer discovery still requires a signaling endpoint.

## Deploy with Docker

For a local Docker run, copy `.env.example` to `.env`; it uses development cookie settings and the public PeerJS signaling fallback. This is not a public production configuration.

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
docker compose logs -f
```

Compose binds the app only to `127.0.0.1:3000`, persists SQLite in the `relay_data` volume, and runs the container with a read-only root filesystem, dropped Linux capabilities, and a healthcheck. Stop it with `docker compose down`; the named database volume is retained. For production, set `NODE_ENV=production`, provide a TLS reverse proxy, and set `TRUST_PROXY=true` only when direct app-port access is blocked and the proxy overwrites `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`. The app serves its pinned PeerJS browser client locally; `PEER_HOST`, `PEER_PORT`, `PEER_PATH`, and `PEER_SECURE` configure the separately operated signaling service. A blank `PEER_HOST` uses PeerJS's public signaling service, suitable only for local evaluation, not a self-hosted production deployment.

For a local-only Docker smoke run without HTTPS, first build with `docker build -t relay-messenger .`, then run `docker run --rm -e NODE_ENV=development -p 3000:3000 -v relay-data:/data relay-messenger`; that uses the public PeerJS signaling service unless configured otherwise. Real Lightning or on-chain transfers still require users' wallets and network access. The app container does not run a Bitcoin or Lightning node.

## Deploy on Render

The `render.yaml` Blueprint creates a single Node web service with a persistent disk for SQLite, HTTPS-aware session cookies, and `/healthz` checks. In Render, create a new Blueprint from the GitHub repository and apply the `relay-messenger` service. Persistent disks require a paid Render instance and keep this service single-instance.

The default Blueprint uses testnet and PeerJS's public signaling service. To use your own signaling server, set `PEER_HOST`, `PEER_PORT`, `PEER_PATH`, and `PEER_SECURE` in the Render service environment. Change `BTC_NETWORK` to `mainnet` only when the app and users' wallets are intentionally configured for real Bitcoin. Keep `NODE_ENV=production` and `TRUST_PROXY=true` on Render so secure cookies and forwarded HTTPS handling work through Render's proxy.

Render deployment still requires the repository to exist on GitHub and a Render account. Do not add wallet secrets or private keys as environment variables; the app never needs them.

## Deploy on Railway

In Railway, deploy the repository with the included Dockerfile, then attach a persistent volume mounted at `/var/data`. Set `DATABASE_PATH=/var/data/users.sqlite`, `NODE_ENV=production`, and `BTC_NETWORK=testnet` in the service variables. Set the healthcheck path to `/healthz`.

Railway mounts volumes as root. Because this image normally runs as the unprivileged `node` user, set Railway's platform variable `RAILWAY_RUN_UID=0` for this service if the mounted directory is not writable; this runs the app process as root inside the container. Use that override only on Railway when needed. The app also detects Railway's `RAILWAY_VOLUME_MOUNT_PATH` automatically if `DATABASE_PATH` is omitted, and fails with a clear startup error if it detects Railway but no volume is mounted.

For private signaling, configure `PEER_HOST`, `PEER_PORT`, `PEER_PATH`, and `PEER_SECURE`. If `PEER_HOST` is blank, browsers use the public PeerJS signaling service. Do not switch `BTC_NETWORK` to `mainnet` until you intentionally want real Bitcoin transactions.

## Run locally

From this folder in PowerShell:

```powershell
npm.cmd ci
npm.cmd start
```

Open <http://127.0.0.1:3000>, choose **Create account**, then sign in. Stop the server with Ctrl+C. Run the automated auth test with:

```powershell
npm.cmd test
```

## Account data

By default, account and session records are stored in `data/users.sqlite`. The server creates this folder and database automatically. The `data/` directory is excluded from Git. To choose another database location, set `DATABASE_PATH` before starting the server.

Back up the database using SQLite's online backup mechanism or stop the server before copying the database file. Keep backups private: they contain account email addresses and password hashes.

## Other devices and deployment

The default bind address (`127.0.0.1`) only accepts connections from the same computer. For a trusted local-network demo, set `HOST=0.0.0.0` and allow the chosen port through the host firewall. Plain HTTP exposes passwords and session traffic to the network, so do not use that setup on an untrusted network or for real accounts.

For internet use, put the app behind a reverse proxy that provides HTTPS, keep the Node server private behind that proxy, and set `NODE_ENV=production` so session cookies receive the `Secure` attribute. Set `TRUST_PROXY=true` only when the proxy overwrites `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, and direct access to Node is blocked. Configure `PORT` if the proxy expects a different local port. The app checks request origins for state-changing API calls, sends restrictive browser security headers including a per-response Content Security Policy nonce, limits request size, and exposes `/healthz` for readiness checks.

Login and registration attempts are limited per client address in memory. These limits reset when the process restarts and are not shared across multiple server processes. Keep this deployment to a single app instance unless you add a shared rate limiter and replace SQLite with a database suitable for concurrent replicas. Before a public launch, set up TLS and DNS, firewalling, persistent encrypted backups and restore tests, monitoring/alerting, dependency and container image update procedures, email verification, password recovery, privacy/retention disclosures, and an incident response plan. Have the authentication and payment UX reviewed for your legal and consumer-protection requirements. This is a deployable single-instance application, not a complete managed production service until those operator-specific controls are configured.

## Peer-to-peer Bitcoin transfers

This app does not sell anything, receive users' funds, or unlock features. Each user may save a public Bitcoin receive address in their account. When two users connect, their browsers share those public addresses over the PeerJS data channel. A sender enters an amount and opens a standard BIP21 `bitcoin:` payment link in their own wallet. Funds go directly from the sender's wallet to the peer's wallet; the app never has custody or access to wallet keys.

Choose the address network before starting the server. Testnet is the safe default:

```powershell
$env:BTC_NETWORK = "testnet"
npm.cmd start
```

For mainnet, set `$env:BTC_NETWORK = "mainnet"` before `npm.cmd start`, and save a mainnet receiving address in the account. Both connected peers must be using the same network. Stop the server with Ctrl+C before changing the environment variable.

Only enter public receive addresses, never private keys or recovery phrases. The app supports the UniSat browser extension through its injected `window.unisat` API. Select the same network in UniSat as the server, connect the wallet, connect to your peer, and enter the amount in BTC. The app requests the wallet to send that amount directly to the peer; the wallet asks the user to approve and handles signing, broadcasting, and the miner fee. The recipient amount is separate from the miner fee. The site collects no fee and never receives or controls funds.

Review the destination address, recipient amount, and miner fee in the wallet confirmation before approving. Transactions are generally irreversible. UniSat must be installed in a supported desktop browser for direct sending; otherwise use the displayed public address and the `bitcoin:` wallet handoff link. The app reports the transaction ID returned by the wallet but does not independently verify transaction confirmation.

## Lightning Network

For off-chain Bitcoin payments, peers share Lightning invoices directly over the PeerJS data channel. The website charges no fee, does not hold funds, and does not store invoices. Treat peer IDs as public and invoice text as sensitive until it expires or is paid; the data channel is encrypted in transit, but the app does not provide end-to-end identity verification or settlement verification.

**No browser extension:** install/open a Lightning wallet app on your phone or computer. The receiver creates an invoice in that wallet app, opens **Use a wallet without a browser extension** in the chat, pastes the invoice, and shares it with the connected peer. The payer can copy the invoice into their wallet or open its `lightning:` link on a device with a compatible wallet. This avoids installing a browser extension in the desktop browser.

**Optional WebLN wallet:** a WebLN-compatible browser wallet can connect to create and pay invoices in the page. Both peers still need a wallet; WebLN only removes manual invoice copying. The receiver's wallet must stay online and the invoice must remain valid until paid. Lightning wallets may impose invoice expiry, liquidity, balance, and routing requirements. Always check the actual invoice amount and routing fee in the wallet before confirming. The app displays the success response reported by the payer's wallet; it does not independently verify settlement with the receiver's node.