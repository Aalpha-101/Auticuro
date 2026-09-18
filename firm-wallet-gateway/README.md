## Firm Wallet Gateway Service

### Introduction
The firm wallet gateway service acts as a transparent proxy of the firm wallet service for ease of client integration.
The firm wallet gateway service is responsible for lead probing, and it will retry infinitely when the downstream firm 
wallet service is not available(during leader change) until success. 

### Configuration

See the configuration file at `.env`, including the service address of `DOWNSTREAM_SERVICE` and port for `Posting Service`
gRPC server.

Airwallex webhook receiver configuration:

- `AIRWALLEX_WEBHOOK_BIND_ADDR`: HTTP bind address for the webhook listener. Defaults to `127.0.0.1`.
- `AIRWALLEX_WEBHOOK_PORT`: HTTP port for the webhook listener. Defaults to `18081`.
- `AIRWALLEX_WEBHOOK_SECRET`: shared secret used to verify the `x-timestamp` + raw-body HMAC signature on
  `POST /webhooks/airwallex`.

The gateway only receives and records authenticated Airwallex webhook notifications. It does **not** initiate,
approve, or execute transfers based on webhook delivery.

For local development, keep the webhook listener bound to localhost and tunnel or proxy requests into
`http://127.0.0.1:18081/webhooks/airwallex`.

For production deployment, keep the internal listener on a trusted network address and expose it only through a
public HTTPS reverse proxy or load balancer that terminates TLS before forwarding to
`POST /webhooks/airwallex`. Do not deploy the listener directly on the public internet without HTTPS. The current
bounded in-memory deduplication store is suitable for development and single-process deployments only; replace it
with durable shared storage before relying on webhook deduplication across restarts or multiple replicas.

### Run Service

1. Start the Firm Wallet Service
2. Start Firm Wallet Gateway Service

```
sh run_gateway.sh
```
