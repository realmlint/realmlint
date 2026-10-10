# Backups to your own storage

`realmlint-agent` can write each realm's export to storage you own, once a
day: an S3 bucket, an S3-compatible service, or a directory. The files are
the snapshots the agent already takes, in the shape of `kc.sh export`, with
secrets masked.

The agent writes with **its own credentials**: an IAM role or access keys in
the environment it runs in. realmlint never sees them and never reads the
backups.

- [How it works](#how-it-works)
- [Amazon S3](#amazon-s3)
  - [1. Create the bucket](#1-create-the-bucket)
  - [2. Allow the agent to write](#2-allow-the-agent-to-write)
  - [3. Give the agent credentials](#3-give-the-agent-credentials)
- [S3-compatible storage](#s3-compatible-storage)
- [A directory](#a-directory)
- [Check that it works](#check-that-it-works)
- [Restore a realm](#restore-a-realm)
- [Troubleshooting](#troubleshooting)

## How it works

1. Start the agent with `--backup-to` (or `REALMLINT_BACKUP_TO`) set to
   `s3://bucket/prefix` or a directory.
2. With hosted realmlint, an owner turns on **Backups to your own storage**
   on the instance's page. The agent asks realmlint whether backups are on
   and writes nothing while they are off. Without `--push-url` (`--out`
   mode), it backs up whenever `--backup-to` is set.
3. The first backup runs with the next snapshot, then every 24 hours
   (`--backup-every`, at least `1h`).
4. Each realm goes to `<prefix>/<realm>/<UTC time>.json`, for example
   `keycloak/prod/acme/2026-10-10T162116Z.json`. The agent reports the time,
   target and any error to realmlint, which shows them on the instance page.

The agent only ever adds files. To remove old ones, add a lifecycle rule to
the bucket, or a cleanup job for a directory.

## Amazon S3

### 1. Create the bucket

Use a bucket only for these backups, in the region closest to your Keycloak.
New buckets block public access and encrypt objects (SSE-S3) by default.

```
aws s3api create-bucket --bucket acme-keycloak-backups --region eu-west-2 \
  --create-bucket-configuration LocationConstraint=eu-west-2
```

Keep 90 days of backups, for example:

```
aws s3api put-bucket-lifecycle-configuration --bucket acme-keycloak-backups \
  --lifecycle-configuration '{"Rules":[{"ID":"expire-realmlint","Status":"Enabled",
    "Filter":{"Prefix":"keycloak/"},"Expiration":{"Days":90}}]}'
```

Turning on versioning or Object Lock as well protects backups from being
deleted, even by someone holding the agent's credentials.

### 2. Allow the agent to write

The agent needs one permission: `s3:PutObject` under its prefix. It does not
list, read or delete. Attach this policy to the role or user the agent runs
as:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-keycloak-backups/keycloak/*"
    }
  ]
}
```

If the bucket encrypts with your own KMS key (SSE-KMS), also allow
`kms:GenerateDataKey` on that key.

### 3. Give the agent credentials

The agent uses the standard AWS credential chain:
1. environment variables;
2. a shared credentials file and `AWS_PROFILE`;
3. web identity on EKS, and the container or instance role.

Always set **`AWS_REGION`** to the bucket's region. Without it, the agent
uses `us-east-1`, and a bucket elsewhere refuses the upload.

Pick the setup that matches where the agent runs:

**On EC2.** Attach an instance profile with the policy, and set
`AWS_REGION`. No keys are needed. In Docker on EC2, containers reach the
instance's role only if the instance metadata hop limit is 2:

```
aws ec2 modify-instance-metadata-options --instance-id i-0123456789abcdef0 \
  --http-put-response-hop-limit 2 --http-tokens required
```

**On ECS.** Put the policy on the task role, not the task execution role.

**On EKS.** Use IAM Roles for Service Accounts or EKS Pod Identity:
1. Create a ServiceAccount for the agent and link it to a role with the
   policy. With IAM Roles for Service Accounts, that link is the annotation
   `eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/realmlint-agent-backups`.
2. Set `serviceAccountName` on the agent's Deployment.
3. Add `AWS_REGION` to its environment.

**Elsewhere, with access keys.** Create an IAM user with only this policy
and an access key. Then:

- **Docker:**

  ```
  docker run -d --name realmlint-agent --restart unless-stopped \
    -e REALMLINT_KEYCLOAK_URL=https://sso.example.com \
    -e REALMLINT_CLIENT_SECRET=... -e REALMLINT_AGENT_TOKEN=... \
    -e AWS_REGION=eu-west-2 -e AWS_ACCESS_KEY_ID=AKIA... -e AWS_SECRET_ACCESS_KEY=... \
    ghcr.io/realmlint/realmlint-agent --push-url https://... --interval 15m \
    --backup-to s3://acme-keycloak-backups/keycloak/prod
  ```

  To keep the keys out of the command line, use `--env-file`. To use a
  credentials file instead, mount it read-only and point the agent at it:

  ```
  -v /etc/realmlint/aws:/aws:ro -e AWS_SHARED_CREDENTIALS_FILE=/aws/credentials -e AWS_PROFILE=backup
  ```

- **systemd:** add the variables to the agent's `EnvironmentFile`
  (`/etc/realmlint-agent.env`, mode 0600), and `--backup-to` to `ExecStart`:

  ```
  AWS_REGION=eu-west-2
  AWS_ACCESS_KEY_ID=AKIA...
  AWS_SECRET_ACCESS_KEY=...
  ```

  The unit realmlint suggests runs as a `DynamicUser` with no home
  directory, so use these variables rather than `~/.aws`.

- **Kubernetes outside AWS:** put the variables in the agent's Secret and
  reference them with `secretKeyRef`, as for the client secret.

## S3-compatible storage

MinIO, Ceph, Cloudflare R2, Backblaze B2, Wasabi and other S3-compatible
services work the same way. Set **`REALMLINT_BACKUP_S3_ENDPOINT`** to the
service's S3 endpoint, and the keys it issued as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. The agent uses path-style requests
(`https://endpoint/bucket/key`).

```
REALMLINT_BACKUP_S3_ENDPOINT=https://minio.internal:9000
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1          # what the service expects; R2 uses "auto"
realmlint-agent ... --backup-to s3://keycloak-backups/prod
```

Create the bucket first. Give the keys write access to the prefix and no
more, if the service supports it.

## A directory

`--backup-to /path` writes to a local directory or a mounted volume (NFS,
SMB, a disk that is itself backed up). The agent creates subdirectories as
needed. Each file is written to a temporary name and then renamed, so a
half-written backup never looks complete.

- **Docker:** the image runs as user 65532 and can write to `/data`. Use a
  volume:

  ```
  -v realmlint-agent:/data ... --backup-to /data/backups
  ```

- **systemd:** the suggested unit makes the file system read-only. Add
  `StateDirectory=realmlint-agent` to `[Service]` and use
  `--backup-to /var/lib/realmlint-agent/backups`.

## Check that it works

The agent logs each backup:

```
backup: 3 realms written to s3://acme-keycloak-backups/keycloak/prod
```

The instance page in realmlint shows the time of the last good backup,
where it went, and the last error.

To test the credentials without waiting a day, run the agent once with
`--out` and `--backup-to`. Without `--push-url` it backs up straight away:

```
REALMLINT_CLIENT_SECRET=... AWS_REGION=eu-west-2 realmlint-agent \
  --keycloak-url https://sso.example.com --out /tmp/rl-test \
  --backup-to s3://acme-keycloak-backups/keycloak/test
```

## Restore a realm

A backup is a realm export with secrets masked. To restore one:

1. Download the file you want:

   ```
   aws s3 cp s3://acme-keycloak-backups/keycloak/prod/acme/2026-10-10T162116Z.json acme.json
   ```

2. Import it with whichever you prefer:
   - `kc.sh import --file acme.json` while Keycloak is stopped, to create the
     realm. Add `--override false` to skip a realm that already exists.
   - The admin console: **Realm settings → Action → Partial import**, to
     bring back clients, roles, groups or identity providers into a running
     realm.

3. Set the secrets again. Client secrets, identity provider secrets and
   SMTP passwords are masked in backups. Generate new client secrets on each
   client's **Credentials** tab, and enter the others again.

Users' passwords are not in the backups. Restored users keep their
accounts, roles and groups, but sign in through a password reset or your
identity provider.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `get credentials: failed to refresh cached credentials, no EC2 IMDS role found` | The agent found no credentials. Set `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, attach a role, or in Docker on EC2 raise the metadata hop limit to 2. |
| `AccessDenied` | The policy does not allow `s3:PutObject` on this bucket and prefix, or (with SSE-KMS) `kms:GenerateDataKey` on the key. |
| `PermanentRedirect` or `AuthorizationHeaderMalformed` | `AWS_REGION` is not the bucket's region. |
| `NoSuchBucket` | The bucket does not exist, or `REALMLINT_BACKUP_S3_ENDPOINT` points at the wrong service. |
| `Backups are on in realmlint, but this agent has no --backup-to target.` | The agent was started without `--backup-to`. Add it and restart the agent. |
| `backup: off for this instance in realmlint` | An owner has not turned on backups on the instance page yet. |
