#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone

from confluent_kafka import Consumer, Producer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPIC = os.environ.get("KAFKA_INPUT_TOPIC", "security.dependency.events")
INCIDENT_TOPIC = os.environ.get("KAFKA_INCIDENT_TOPIC", "security.incidents")
GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "dependency-security-agent")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_incident(event: dict) -> dict:
    severity = "critical" if event.get("status") == "block" else "high"

    return {
        "incident_type": "dependency_supply_chain_risk",
        "created_at": utc_now(),
        "severity": severity,
        "repository": event.get("repository"),
        "pipeline_id": event.get("pipeline_id"),
        "commit_sha": event.get("commit_sha"),
        "status": event.get("status"),
        "summary": event.get("summary", {}),
        "blocked": event.get("blocked", []),
        "quarantined": event.get("quarantined", []),
        "recommended_actions": [
            "Fail pipeline immediately" if event.get("status") == "block" else "Quarantine artifact",
            "Open security incident",
            "Require manual security review",
            "Prevent production promotion",
            "Update central denylist/policy",
        ],
    }


def main() -> int:
    consumer = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
        }
    )
    producer = Producer({"bootstrap.servers": BOOTSTRAP})

    consumer.subscribe([INPUT_TOPIC])
    print(f"Listening on topic: {INPUT_TOPIC}")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print(f"Consumer error: {msg.error()}", file=sys.stderr)
                continue

            try:
                event = json.loads(msg.value().decode("utf-8"))
                status = event.get("status")

                if status in ("block", "quarantine"):
                    incident = create_incident(event)
                    producer.produce(INCIDENT_TOPIC, json.dumps(incident).encode("utf-8"))
                    producer.flush()
                    print(f"Incident created for repo={event.get('repository')} status={status}")
                else:
                    print(f"Allowed dependency set for repo={event.get('repository')}")
            except Exception as exc:
                print(f"Processing error: {exc}", file=sys.stderr)

    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
