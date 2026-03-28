# 2FApi Extensions

Zero-Knowledge Proof authentication as native database extensions.

Instead of adding 2FApi as an application middleware, these extensions bring ZKP authentication **directly into the database engine**. Row-Level Security in PostgreSQL or key-level ACLs in Redis enforce access control at the data layer — impossible to bypass from application code.

## Architecture

```
extensions/
├── pg-extension/        # PostgreSQL extension (via pgrx — Rust)
│   ├── src/
│   │   ├── lib.rs       # Extension entry point
│   │   ├── enroll.rs    # CREATE EXTENSION pg_2fapi → twofapi.enroll()
│   │   ├── challenge.rs # twofapi.challenge()
│   │   ├── verify.rs    # twofapi.verify()
│   │   ├── session.rs   # twofapi.authenticate() + twofapi.current_client()
│   │   └── rls.rs       # Row-Level Security integration helpers
│   ├── Cargo.toml
│   ├── pg_2fapi.control # PostgreSQL extension metadata
│   └── sql/
│       └── pg_2fapi--1.0.sql  # Extension SQL setup
│
├── redis-module/        # Redis module (via redis-module-rs — Rust)
│   ├── src/
│   │   ├── lib.rs       # Module entry point
│   │   ├── enroll.rs    # 2FAPI.ENROLL command
│   │   ├── challenge.rs # 2FAPI.CHALLENGE command
│   │   ├── verify.rs    # 2FAPI.VERIFY command
│   │   └── acl.rs       # Key-level access control
│   └── Cargo.toml
│
└── README.md            # This file

All extensions share the same crypto core:
  crypto-core/src/       # Pedersen commitments, Sigma proofs, Fiat-Shamir
```

## Shared Crypto Core

Every extension links against `twofapi-crypto-core` (the same Rust crate used by the Node.js NAPI bindings). No code duplication — one crypto implementation, multiple interfaces.

## Future Extensions

The `extensions/` directory is designed to grow:
- `mysql-plugin/` — MySQL authentication plugin
- `mongo-extension/` — MongoDB enterprise auth mechanism
- `nginx-module/` — Nginx subrequest authentication
- `envoy-filter/` — Envoy proxy WASM filter
- `kong-plugin/` — Kong API gateway plugin
