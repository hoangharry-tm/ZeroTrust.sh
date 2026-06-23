# IDOR Chain — Cross-Service BOLA Testbed

A 3-microservice e-commerce platform designed to exercise ZeroTrust.sh's Path B
cross-surface vulnerability detection. The BOLA/IDOR vulnerability spans all three
services: `orderId` flows from the HTTP request through the Go gateway to the
Python order service and finally to the Java payment service — without any
ownership verification at any hop.

## Architecture

```
User → Go Gateway (:8080) → Python Orders (:5000) → Java Payment (:8090)
```

## Vulnerability Chain

1. **Gateway** — `GET /api/orders?orderId=X&userId=Y` proxies to Orders service
   without checking if `userId` owns `orderId` (BOLA: missing access control)

2. **Orders** — `GET /orders/<order_id>` queries by orderId without userId filter
   (IDOR: missing ownership check in SQL query)

3. **Payment** — `POST /api/payments/charge` processes payment without verifying
   the requesting user owns the order (IDOR: missing authorization at sink)

## Run

```bash
docker compose up
```
