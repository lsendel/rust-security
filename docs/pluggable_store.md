# Pluggable Identity Store

The authentication service features a pluggable storage backend, allowing you to choose where user, group, and token data is persisted. This provides flexibility to integrate the service into different environments, from simple in-memory setups for testing to robust, persistent SQL databases for production.

This is achieved through a generic `Store` trait located in the `common` crate. Any struct that implements this trait can be used as a storage backend for the `auth-service`.

## Supported Backends

Out of the box, the following backends are provided:

### 1. `HybridStore` (Default)

-   **Backend Name**: `hybrid`
-   **Description**: This is the default store. It maintains the original behavior of the service for backward compatibility.
    -   **Users and Groups**: Stored purely in-memory. This data will be lost on restart.
    -   **Tokens and Auth Codes**: Stored in a hybrid model. Data is kept in-memory but is also written to **Redis** if a `REDIS_URL` is provided. This allows for token sharing and persistence across multiple service instances.
-   **Use Case**: Ideal for development, testing, or deployments where user data is managed externally and the service only needs to handle ephemeral token data.

### 2. `SqlStore`

-   **Backend Name**: `sql`
-   **Description**: This backend stores all data—users, groups, tokens, and auth codes—in a persistent SQL database. It currently supports **PostgreSQL**.
-   **Use Case**: Recommended for production environments where the `auth-service` is the primary source of truth for user and group identities, or when data persistence is required.

## Configuration

You can select and configure the storage backend using the following environment variables:

-   `STORE_BACKEND`: Specifies which backend to use.
    -   `hybrid` (default)
    -   `sql`
-   `DATABASE_URL`: The connection string for the SQL database. **This is required if `STORE_BACKEND` is set to `sql`**.
    -   Example: `postgres://user:password@localhost:5432/auth_db`
-   `REDIS_URL`: The connection string for Redis. This is used by the `hybrid` store.
    -   Example: `redis://localhost:6379`

### Example Configurations

**Hybrid Store (Default)**
```bash
# No configuration needed for the most basic in-memory setup.
# To enable Redis for token persistence:
REDIS_URL=redis://redis-instance:6379
```

**SQL Store**
```bash
STORE_BACKEND=sql
DATABASE_URL=postgres://myuser:mypass@my-postgres:5432/auth_service
```

## SQL Store Schema

If you are using the `SqlStore` backend, the service will automatically run migrations on startup to create the necessary tables. The schema is defined in `auth-service/migrations/`.

Here is the current schema:
```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    user_name TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    nonce TEXT,
    scope TEXT NOT NULL,
    pkce_challenge TEXT,
    pkce_method TEXT,
    user_id TEXT,
    exp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    token_display TEXT NOT NULL, -- For logging/display purposes
    active BOOLEAN NOT NULL,
    scope TEXT,
    client_id TEXT,
    exp BIGINT,
    iat BIGINT,
    sub TEXT,
    token_binding TEXT,
    mfa_verified BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    refresh_token_hash TEXT PRIMARY KEY NOT NULL,
    access_token_hash TEXT NOT NULL,
    exp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_token_reuse (
    refresh_token_hash TEXT PRIMARY KEY NOT NULL,
    exp BIGINT NOT NULL
);
```

## Implementing a Custom Store

To support a different database (e.g., MySQL, DynamoDB), you can create your own store by implementing the `common::Store` trait.

1.  **Create a new struct** for your store (e.g., `MySqlStore`).
2.  **Implement the `common::Store` trait** for your struct. This will require you to write the logic for all the methods defined in the trait.
3.  **Update the configuration** in `auth-service/src/config.rs` to add your new backend to the `StoreBackend` enum.
4.  **Update the initialization logic** in `auth-service/src/main.rs` to construct and use your new store when it's selected in the configuration.
```
