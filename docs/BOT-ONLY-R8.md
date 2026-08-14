# Bot-only beta.1 R8 — idempotent router credential lifecycle

R8 fixes duplicate managed API keys created when switching between 9router and
OmniRoute.

Root cause: R7 started the previously stopped provider and immediately tested
its stored key. During provider startup, connection/transient failures were
treated as invalid credentials, so a new key was provisioned.

R8 behavior:

- waits for the selected provider to become ready before validating its key;
- reuses a valid stored key;
- rotates only when the provider explicitly returns HTTP 401/403;
- refuses key rotation for connection errors, timeouts, 5xx responses, or
  other transient/non-authentication failures;
- keeps switching between routers idempotent;
- adds `./hermesctl router cleanup-keys all` to remove stale duplicate keys
  already created by R7 while preserving the currently configured key;
- never prints raw key material.

Expected repeated switching:

```text
./hermesctl router set nine-router
[ok] managed 9router API key is already valid

./hermesctl router set omniroute
[ok] managed OmniRoute API key is already valid

./hermesctl router set nine-router
[ok] managed 9router API key is already valid
```

No additional managed key should be created.
