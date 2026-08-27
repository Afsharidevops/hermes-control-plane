# Artifact Mirroring and Offline Supply

**Runtime-complete, controlled artifact path.** Hermes mirrors and verifies explicitly identified artifacts for governed workloads and Cluster Factory. It is not an unrestricted downloader, generic repository proxy, or credential store.

## Supported artifact kinds

| Kind | Controlled capability |
|---|---|
| `oci-image` | Registry-to-registry image copy with digest validation. |
| `helm-chart` | OCI chart copy with Helm media-type validation. |
| `package` | File or allowlisted HTTPS blob synchronization. |
| `git-release` | Exact-tag release archive synchronization. |
| `ansible-collection` | Collection archive verification and synchronization. |
| `apt-repository` | Signed APT repository snapshot. |
| `rpm-repository` | Signed RPM repository snapshot. |
| `python-repository` | Signed/controlled Python repository snapshot. |

Unsupported protocols and unconstrained repository layouts remain **Contract-only/deferred**. Do not use a generic URL to work around an allowlist.

## Preconditions and configuration

1. Set exact source/destination hosts in `HERMES_ARTIFACT_HTTPS_HOST_ALLOWLIST`, `HERMES_ARTIFACT_OCI_SOURCE_REGISTRY_ALLOWLIST`, and `HERMES_ARTIFACT_OCI_DESTINATION_REGISTRY_ALLOWLIST`. Empty values disable corresponding network paths.
2. Mount trusted authentication material/keyrings read-only through `HERMES_ARTIFACT_AUTH_HOST_PATH` and reference only approved paths under the container secret root.
3. Keep byte, timeout, expanded repository, and metadata limits at reviewed bounded values.
4. Configure provider offline repository URLs only when their source and signing policy are established.

Never store registry passwords, token text, or signing private keys in an artifact item, ChangeSet, or audit record.

## Mirror workflow

1. Create an artifact item with its exact digest, immutable version, or exact Git tag as required by its kind.
2. Hermes validates kind-specific source/destination allowlists and trusted transport material.
3. Mirror through the restricted source/registry root using atomic, idempotent publication.
4. Verify digests, chart media types, release/collection/archive signatures or repository metadata as applicable.
5. Review the resulting safe metadata/evidence state. `READY` denotes that the exact item met expected controlled checks; `BLOCKED` requires correction.
6. For a ClusterBlueprint, resolve dependencies into a deterministic manifest, then bind the exact READY manifest to the provisioning/operation plan.

A digest, version, allowlist, source, destination, or manifest change invalidates dependent planning/approval assumptions.

## Security properties

- Explicit version/digest identity is mandatory.
- Source and destination are exact allowlisted hosts.
- File/registry roots are controlled; publication is atomic/idempotent.
- Secret material is available only through mounted trusted files.
- Plans, audit, UI, and router services receive safe reference/evidence data only.
- Mirror behavior is ChangeSet/authorization aware for governed operations.

## Operator troubleshooting

| Result | Likely action |
|---|---|
| HTTPS/OCI path unavailable | Verify exact allowlist spelling and keep the path disabled until reviewed. |
| Authentication/keyring failure | Check mounted credential reference and allowed container path; do not paste secret content into logs. |
| Digest/media/signature mismatch | Treat source as untrusted; obtain a correct immutable artifact identity. |
| Manifest `BLOCKED` | Resolve every blocked dependency and regenerate the plan/approval. |
| Transfer limit/timeout | Review expected artifact size and configured bound; raise only through controlled change review. |

See [Configuration](configuration.md), [Cluster Factory](cluster-factory.md), and [Governance](governance-and-changes.md).
