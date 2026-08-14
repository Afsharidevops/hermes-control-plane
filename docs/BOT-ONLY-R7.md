# Bot-only beta.1 R7 — symmetric router credential provisioning

R7 extends automatic runtime API-key provisioning from 9router to OmniRoute.

## OmniRoute bootstrap

When OmniRoute is active, `./hermesctl up`:

1. starts OmniRoute as a bootstrap phase;
2. reuses the stored `OMNIROUTE_UPSTREAM_API_KEY` when it is still valid;
3. otherwise performs one loopback management login using the generated
   `OMNIROUTE_INITIAL_PASSWORD`;
4. creates a dedicated runtime key with `POST /api/keys`;
5. requests only the non-management `chat` scope;
6. stores the raw key once in local `.env`;
7. verifies the key against the separate OmniRoute API port `/v1/models`;
8. recreates Router Gateway with the managed key.

The automation sends no browser `Origin` header. It is a server-to-server
management request authenticated by the dashboard session cookie.

No infrastructure credential is exposed to Hermes or Smart Router.

## Symmetric commands

```bash
./hermesctl router set nine-router
./hermesctl router set omniroute

./hermesctl router provision nine-router
./hermesctl router provision omniroute
```

With `HERMES_ENABLE_BOTH_ROUTERS=true`, `./hermesctl up` provisions and verifies
both router credentials independently.
