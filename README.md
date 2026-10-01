# Backend Logic System

A modular collection of production-oriented backend building blocks covering API protocols, authentication, traffic management, search indexing, and containerized delivery. Each module is self-contained, independently reviewable, and designed around well-established engineering patterns.

---

## Overview

- **Purpose**
  - Provide reference implementations of core backend concerns in isolated, composable modules
  - Demonstrate protocol-level and security-focused design decisions across Python, Node.js, and Go
- **Design principles**
  - Separation of concerns: one module per responsibility
  - Defense in depth: validation, hashing, rate limiting, and origin control applied at distinct layers
  - Configurability: tunable thresholds, TTLs, and strategies exposed through constructor options or environment variables
  - Explicit failure modes: typed exceptions and structured error codes

---

## Repository Structure

```
Backend-Logic-Systems/
├── API-Protocols/
│   ├── REST-API/
│   ├── GraphQL/
│   ├── WebSocket/
│   ├── gRPC/
│   └── greeter.proto
├── JWT-Authentication/
├── OTP-Authentication/
├── Pocketbase-Auth/
├── Bcrypt_Hash.py
├── CORS.py
├── Load-Balancing-Server/
├── Rate Limiting Module /
├── ElasticSearch/
└── Docker/
```

---

## Modules

### API Protocols

- **REST**
  - Resource-oriented server with a companion client
  - Server-Sent Events (SSE) server for unidirectional, long-lived event streams
- **GraphQL**
  - Schema-driven server exposing queries and mutations
  - Permission-based field and operation access control
  - Dedicated client implementation
- **WebSocket**
  - Full-duplex, persistent connection server and client
- **gRPC**
  - Contract-first design using Protocol Buffers (`greeter.proto`)
  - Generated stubs for strongly typed server and client communication

### JWT Authentication

- **Token service**
  - Access and refresh token pair generation with independent secrets
  - HS256 signing with issuer and audience claims
  - Unique `jti` per token for traceability and revocation readiness
  - Configurable expiry via environment variables
- **Controller**
  - Login, token refresh, and logout flows
  - Normalized error responses that avoid user enumeration
- **Middleware**
  - Bearer token extraction and verification
  - Dedicated refresh-token verification path
  - Differentiated status codes for expired and invalid tokens

### OTP Authentication

- **Generation and verification**
  - Numeric OTP with configurable length and TTL
  - TOTP support with drift tolerance window
  - Constant-time comparison to mitigate timing attacks
- **Abuse protection**
  - Maximum attempt counter with timed lockout
  - Single-use enforcement
- **Storage abstraction**
  - Pluggable backends: in-memory store and Redis store
- **Error model**
  - Distinct exceptions for expired, invalid, locked, and already-used codes

### Password Hashing

- **Bcrypt implementation**
  - Configurable work factor bounded to a safe range (10 to 14)
  - Password policy enforcement before hashing
  - Handling of bcrypt's 72-byte input limit
  - Typed exceptions for policy and runtime failures
- **Reuse**
  - Utility variant included within the OTP module

### PocketBase Authentication

- **Backend**
  - Go service embedding PocketBase with built-in JWT auth and admin UI
  - SQLite-backed persistence
- **Frontend**
  - React and Vite client integrating with the PocketBase auth API

### CORS Policy Enforcement

- **Origin allowlist validation**
  - Strict origin matching against a configured list
- **Preflight handling**
  - Method and header allowlists
  - Credentialed request support
  - Configurable preflight cache duration
  - Exposed response headers
- **Rejection path**
  - Dedicated exception for forbidden origins

### Load Balancer

- **Algorithms**
  - Round robin
  - Least connections
  - Weighted round robin
  - IP hash for client affinity
- **Reliability**
  - Periodic active health checks with configurable interval and timeout
  - Automatic exclusion and reinstatement of unhealthy backends
  - Runtime server registration and removal
- **Operations**
  - Reverse proxying of HTTP and HTTPS traffic
  - Event-driven architecture and runtime statistics

### Rate Limiting

- **Mechanism**
  - Fixed-window request counting per client IP
  - Automatic IP blocking on threshold breach with configurable block duration
- **Controls**
  - Express-style middleware integration
  - Manual block, unblock, and per-IP statistics
  - `X-Forwarded-For` aware client identification
  - Background cleanup of stale records

### Elasticsearch Indexing

- **Index design**
  - Custom analyzer with lowercase and ASCII folding filters
  - Multi-field mappings supporting both full-text and exact-match queries
  - Typed fields including keyword, float, boolean, date, and geo_point
- **Lifecycle operations**
  - Index creation and deletion
  - Single and bulk document indexing
  - Dynamic mapping extension
  - Reindexing to a target index
- **Resilience**
  - Client-level retries and request timeouts

### Docker and CI/CD

- **Compose stack**
  - MongoDB with persistent volume and isolated bridge network
  - Mongo Express administrative interface
- **GitHub Actions workflows**
  - Image build and push with commit-SHA and `latest` tagging via Buildx
  - Deployment pipeline with automated rollback on failure

---

## Technology Stack

- **Languages**: Python, JavaScript (Node.js), Go
- **Protocols**: HTTP, SSE, GraphQL, WebSocket, gRPC
- **Security**: JWT, bcrypt, TOTP, CORS, IP-based throttling
- **Data and search**: MongoDB, Redis, SQLite, Elasticsearch
- **Infrastructure**: Docker, Docker Compose, GitHub Actions

---

## Security Considerations

- **Secrets management**
  - Default credentials and fallback secrets in the source are placeholders and must be replaced through environment configuration
- **Credential handling**
  - The JWT login flow should be paired with the bcrypt module for hashed credential verification in production
- **State management**
  - In-memory stores for OTP and rate limiting are single-instance only; use Redis or an equivalent shared store for horizontally scaled deployments
- **Network exposure**
  - Restrict administrative interfaces and database ports to trusted networks

---

## Conclusion

- Backend Logic System consolidates essential backend patterns into clean, modular, and auditable components.
- It serves as a technical reference for building secure, scalable, and observable services.
