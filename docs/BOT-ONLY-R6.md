# Bot-only beta.1 R6 — automatic 9router API-key provisioning

R6 removes the manual 9router dashboard/API-key step.

When `./hermesctl up` selects 9router, Hermes Control Plane:

1. starts 9router alone as a bootstrap phase;
2. checks whether the locally managed Router Gateway key already works;
3. if needed, authenticates to loopback `/api/auth/login` using the generated
   `NINEROUTER_INITIAL_PASSWORD`;
4. creates a dedicated key through `POST /api/keys` named
   `hermes-control-plane-router-gateway`;
5. stores the returned key only in local `.env` as
   `NINE_ROUTER_UPSTREAM_API_KEY`;
6. verifies it against `/v1/models`;
7. starts Router Gateway and the rest of the stack using that key.

No API key is printed or committed. A failed management login is attempted only
once per provisioning invocation to avoid 9router's dashboard lockout.

Normal operation requires only:

```bash
./hermesctl up
```

A repair command is available:

```bash
./hermesctl router provision nine-router
```
