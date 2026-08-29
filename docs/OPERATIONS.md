# Operations

## 1. Bootstrap the Garage bucket

There is no bucket or S3 key for Sirna until someone makes one, and no
procedure for it exists anywhere in the homelab repo — `garage-secrets` holds
only `rpc-secret`, `admin-token` and `metrics-token`. So this is step one, and
it is written down here because it was not written down anywhere else.

Every `garage` call needs `-c /config/garage.toml`. The config is mounted from a
ConfigMap, not at the default path, and without the flag the CLI fails with
`Unable to read configuration file /etc/garage.toml` — which reads like a broken
install rather than a missing flag.

```bash
G="kubectl -n apps exec garage-0 -- /garage -c /config/garage.toml"

$G status            # check the layout
```

**A fresh Garage has `NO ROLE ASSIGNED` and cannot store anything.** This
homelab's instance ran for four months in that state because nothing had ever
used it. Assign a layout once, before the first bucket:

```bash
NODE=$($G status | grep -A2 "HEALTHY NODES" | tail -1 | awk '{print $1}')
$G layout assign -z homelab -c 15G "$NODE"   # 15G of a 20Gi PVC, leaving headroom
$G layout apply --version 1
```

Then the bucket and key:

```bash
$G bucket create sirna-blobs
$G key create sirna-app
```

**The key ID and secret are printed once.** Capture them now.

```bash
$G bucket allow --read --write sirna-blobs --key sirna-app

# The PVC is shared. An upload endpoint with no quota eventually eats all of it.
$G bucket set-quotas sirna-blobs --max-size 5G
```

`key create` prints the secret once. `$G key info --show-secret sirna-app`
retrieves it later; `$G key list` gives the key ID.

## 2. Create the Secret

Vault has been sealed and unrecoverable since 2026-06-30, so the repo's usual
`VaultStaticSecret` mechanism **will not sync**. Create a plain Secret by hand,
exactly as OTM does.

```bash
kubectl -n apps create secret generic sirna-secrets \
  --from-literal=S3_ACCESS_KEY_ID='<from step 1>' \
  --from-literal=S3_SECRET_ACCESS_KEY='<from step 1>'
```

> **Do not add a `VaultStaticSecret` for this app** until Vault is
> re-initialised. ArgoCD will sync a CRD that never produces a Secret, and the
> pod will CrashLoop with an error that points nowhere near the cause.

## 3. Build and side-load the image

No CI for this repo yet, so the image is built locally and imported into k3d.

```bash
SHA=$(git rev-parse --short=7 HEAD)
docker build -t sirna:$SHA .
k3d image import sirna:$SHA -c homelab
```

Then pin it in `apps/sirna/overlays/production/kustomization.yaml`:

```yaml
images:
  - name: sirna
    newTag: "<SHA>"
```

Never `latest`. A moving tag means two different images can share a name, and
rollback stops meaning anything.

## 4. Networking

Four hops, and each one has bitten this homelab before.

```
Cloudflare → VPS Caddy 2.6.2 → WireGuard → caddy-homelab 2.11 → NodePort 30601 → pod
```

**Firewall: nothing to do, despite what the homelab deployment guide says.**
That guide describes an `INPUT` policy of DROP with per-port allows on `wg0`.
Checked on 2026-08-30, the live policy is **ACCEPT** with no per-NodePort rules,
and OTM on 30102 reaches the outside with no allow rule of its own. Verify
before assuming either way — `iptables -L INPUT -n | head -3` — but do not go
hunting for a rule to copy that does not exist.

**`vps/caddy/Caddyfile.homelab`:**

```caddyfile
:30601 {
    reverse_proxy k3s-node:30601 {
        trusted_proxies 10.10.0.2/32
    }
}
```

Caddy here is 2.11, and since 2.7 `reverse_proxy` **discards** an incoming
`X-Forwarded-For` unless the peer is trusted. Without that line every visitor
appears as `10.10.0.2` and the per-IP rate limiter silently becomes global.

**`vps/caddy/Caddyfile`:**

```caddyfile
sirna.arisjirat.com {
    encode gzip zstd
    reverse_proxy 10.10.0.1:30601 {
        header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}
    }
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
    }
    log {
        output file /var/log/caddy/sirna-access.log {
            roll_size 10MiB
            roll_keep 3
        }
        format console
    }
}
```

VPS Caddy is 2.6.2 and has no `trusted_proxies`, so the chain is straightened
manually from `CF-Connecting-IP`.

**Deploy the VPS Caddyfile manually.** The `vps-deploy` CI cannot reach the VPS
over SSH and has been broken since July.

```bash
scp vps/caddy/Caddyfile root@10.10.0.2:/etc/caddy/Caddyfile
ssh root@10.10.0.2 "caddy validate --config /etc/caddy/Caddyfile"   # before reload, always
ssh root@10.10.0.2 "caddy reload --config /etc/caddy/Caddyfile"
```

Validating first is not optional: a syntax error on reload takes down every
vhost on the VPS at once.

DNS needs no change — `*.arisjirat.com` is already a wildcard.

## 5. Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8080` | |
| `STORE` | `s3` | `fs` for local development, no S3 needed |
| `DB_PATH` | `/data/sirna.db` | SQLite metadata, on the PVC |
| `S3_ENDPOINT` | `http://garage.apps.svc.cluster.local:3900` | |
| `S3_REGION` | `garage` | Garage's configured region name |
| `S3_BUCKET` | `sirna-blobs` | |
| `MAX_BLOB_BYTES` | `33554432` | Must stay below Cloudflare's 100 MB body limit |
| `DEFAULT_TTL_SECS` | `86400` | |
| `MAX_TTL_SECS` | `604800` | |
| `DOWNLOAD_GRACE_SECS` | `300` | See §6 |
| `RATE_BURST` / `RATE_PER_SEC` | `20` / `2.0` | Per client IP |

Path-style S3 addressing is used unconditionally. Garage's `root_domain` is
`.s3.garage.local`, which has no DNS behind it, so virtual-host addressing — the
usual SDK default — would fail to resolve.

## 6. How one-time reads actually behave

A download claims the blob with a single conditional UPDATE; only the
transaction that changes exactly one row may stream. Everyone else gets 410.

Objects are deleted by the **reaper**, not inline at the end of a download, and
not until `DOWNLOAD_GRACE_SECS` has passed. This is deliberate: a reader whose
connection drops mid-transfer would otherwise lose the message permanently with
no recourse. A failed download hands the claim back and increments a counter,
capped at three attempts.

The reaper also collects blobs stuck in `consuming`, which is what a crash
mid-download leaves behind.

## 7. Health and monitoring

| Endpoint | Meaning |
|---|---|
| `/healthz` | The process is up |
| `/readyz` | SQLite responds **and** the object store is reachable |
| `/metrics` | Prometheus text: live count, consumed count, bytes held |

Metrics carry counts only. Nothing is labelled by blob id — a metric with an id
in it would turn Prometheus into a record of who received what.

## 8. Rollback

```bash
# Repin the previous SHA in the overlay and commit; ArgoCD does the rest.
kubectl -n apps rollout status deploy/sirna
```

The image for the previous SHA must still be present in the k3d node. If it has
been pruned, rebuild it from that commit — which is exactly why the overlay pins
a SHA and never `latest`.

## 9. Things that will bite you

- **`readOnlyRootFilesystem: true` plus uploads.** The pod writes nothing to
  disk outside the PVC. Mount an `emptyDir` with a `sizeLimit` at `/tmp` anyway
  as a safety valve, so a stray temp file fails loudly on quota rather than
  mysteriously on `EROFS`.
- **`enableServiceLinks: false`.** Kubernetes injects `SIRNA_PORT=tcp://…`,
  which collides with the app's own `PORT` handling.
- **Single writer.** SQLite on an RWO PVC with `strategy: Recreate` and
  `replicas: 1`. Do not scale this deployment.
