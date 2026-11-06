"""Create per-service RabbitMQ identities with per-queue read permissions."""
import base64
import json
import os
import time
from urllib.parse import quote
import urllib.error
import urllib.request

host = os.environ.get("RABBITMQ_HOST", "rabbitmq")
vhost = os.environ["RABBITMQ_VIRTUAL_HOST"]
admin_user = os.environ["RABBITMQ_ADMIN_USERNAME"]
admin_password = os.environ["RABBITMQ_ADMIN_PASSWORD"]
base = f"http://{host}:15672/api"
auth = "Basic " + base64.b64encode(f"{admin_user}:{admin_password}".encode()).decode()


def request(method: str, path: str, value: dict | None = None) -> None:
    body = None if value is None else json.dumps(value).encode()
    req = urllib.request.Request(
        base + path,
        data=body,
        method=method,
        headers={"Authorization": auth, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=8) as response:
        if response.status not in (200, 201, 204):
            raise RuntimeError("RabbitMQ account provisioning returned an unexpected status")


encoded_vhost = quote(vhost, safe="")
services = {
    "identity": (None, False),
    "agent": ("agent-management", True),
    "policy": ("policy-engine", True),
    "ai_analysis": ("ai-analysis", True),
    "runtime": ("runtime-security-gateway", True),
    "audit": ("audit-service", False),
    "notification": ("notification-service", False),
    "gateway": (None, False),
}

for attempt in range(30):
    try:
        request("GET", "/overview")
        break
    except (urllib.error.URLError, TimeoutError):
        if attempt == 29:
            raise RuntimeError("RabbitMQ management API did not become ready") from None
        time.sleep(2)

for service, (queue_service, can_publish) in services.items():
    username = os.environ[f"RABBITMQ_{service.upper()}_USERNAME"]
    password = os.environ[f"RABBITMQ_{service.upper()}_PASSWORD"]
    user_path = "/users/" + quote(username, safe="")
    request("PUT", user_path, {"password": password, "tags": ""})
    if queue_service is None:
        configure, read = "(?!)", "(?!)"
    else:
        queue = f"agentshield\\.{queue_service}\\.events(\\.dlq)?"
        configure = f"^agentshield\\.events(\\.dlx)?$|^{queue}$"
        read = f"^{queue}$"
    request(
        "PUT",
        f"/permissions/{encoded_vhost}/" + quote(username, safe=""),
        {
            "configure": configure,
            "write": "^agentshield\\.events(\\.dlx)?$" if can_publish else "(?!)",
            "read": read,
        },
    )

print("RabbitMQ per-service users and scoped queue permissions are ready.")
