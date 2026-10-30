# Architecture and security notes

The API owns SQLite persistence and generated storage identifiers. Public key data is stored in queryable columns. Private exponents are encrypted at rest and never sent in ordinary key-list responses. Signing uses a password provided for one request. Package archives are read directly from memory; no uploaded path is extracted.

The browser does not contain cryptographic signing code. It calls the backend endpoints and presents returned status. The dashboard statistics are read from persistent records. Local access is assumed; there is no user/session model wired into routes.

The signature module is intentionally dependency-light and independent of the HTTP layer. It uses a fixed standardized finite-field parameter set, strict parameter checks, secure nonce selection, and reason-coded failures.
