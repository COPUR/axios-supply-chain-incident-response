#!/usr/bin/env python3
import json
import os
import sys

from confluent_kafka import Producer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "security.dependency.events")
RESULT_FILE = os.environ.get("GUARDRAIL_RESULT_FILE", "guardrail-result.json")
PIPELINE_ID = os.environ.get("CI_PIPELINE_ID", "unknown")
REPO = os.environ.get("CI_REPOSITORY", "unknown")
COMMIT_SHA = os.environ.get("CI_COMMIT_SHA", "unknown")


def delivery_report(err, msg):
    if err:
        print(f"Kafka delivery failed: {err}", file=sys.stderr)


def main() -> int:
    with open(RESULT_FILE, "r", encoding="utf-8") as f:
        result = json.load(f)

    payload = {
        "pipeline_id": PIPELINE_ID,
        "repository": REPO,
        "commit_sha": COMMIT_SHA,
        "status": result["status"],
        "summary": result.get("summary", {}),
        "blocked": result.get("blocked", []),
        "quarantined": result.get("quarantined", []),
    }

    producer = Producer({"bootstrap.servers": BOOTSTRAP})
    producer.produce(TOPIC, json.dumps(payload).encode("utf-8"), callback=delivery_report)
    producer.flush()

    print(f"Published guardrail event to {TOPIC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
