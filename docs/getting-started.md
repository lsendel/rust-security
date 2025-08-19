# Getting Started Guide

This guide will help you get the Rust Authentication Service up and running quickly for development and testing.

## Prerequisites

To build and run the service, you will need:

- **Rust**: Version 1.70 or later.
- **Docker**: For running a local Redis instance.

## 1. Clone the Repository

First, clone the repository to your local machine:

```bash
git clone https://github.com/your-org/rust-security.git
cd rust-security
```

## 2. Start Redis

The authentication service uses Redis for session storage and rate limiting. The easiest way to get Redis running is with Docker:

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

## 3. Configure the Service

The service is configured using environment variables. To get started, copy the example environment file:

```bash
cp auth-service/.env.example auth-service/.env
```

The default configuration in `.env` is suitable for local development.

## 4. Build and Run the Service

Now you can build and run the authentication service:

```bash
cargo run -p auth-service
```

The service will start on `http://localhost:8080`.

## 5. Verify the Installation

You can verify that the service is running by sending a request to the health check endpoint:

```bash
curl http://localhost:8080/health
```

You should see the following response:

```json
{
  "status": "ok"
}
```

You can also check the OpenID Connect discovery endpoint:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## Next Steps

Now that you have the service running, you can:

- **Explore the API**: The service provides an OpenAPI specification at `http://localhost:8080/openapi.json`.
- **Integrate with your applications**: See the [Integration Guide](./integration/README.md) for details on how to integrate your applications with the authentication service.
- **Learn more about the architecture**: The [Architecture Overview](./architecture/README.md) provides a high-level overview of the system architecture.
- **Deploy to production**: The [Deployment Guide](./deployment/README.md) explains how to deploy the service to a production environment.