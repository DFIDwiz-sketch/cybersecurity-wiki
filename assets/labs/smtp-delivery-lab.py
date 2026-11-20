"""Classify the last evidenced stage of synthetic, pre-normalized SMTP traces."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Trace:
    relay: str
    queue_id: str
    arrival: str
    recipient: str


@dataclass(frozen=True)
class Observation:
    trace: Trace
    minute: int
    stage: str
    reply: int | None = None


def describe(event):
    if event.stage == "rcpt" and event.reply == 250:
        return "RECIPIENT_ACCEPTED_ONLY"
    if event.stage == "final_reply" and event.reply == 250:
        return "NEXT_HOP_ACCEPTED"
    if event.stage in {"rcpt", "final_reply"} and event.reply is not None:
        if 400 <= event.reply < 500:
            return "TEMPORARY_REPLY"
        if 500 <= event.reply < 600:
            return "PERMANENT_REPLY"
    if event.stage == "final_reply_missing":
        return "HANDOFF_UNCONFIRMED"
    if event.stage == "trusted_quarantine_record":
        return "QUARANTINED"
    if event.stage == "trusted_mailbox_record":
        return "MAILBOX_DELIVERED"
    raise ValueError(f"Unsupported training observation: {event}")


def classify(events, trace):
    matching = [event for event in events if event.trace == trace]
    if not matching:
        return "NO_MATCHING_EVIDENCE"
    latest = max(matching, key=lambda event: event.minute)
    return describe(latest)


def trace(queue_id, name, *, relay="mx-a.example", arrival="2026-11-20T09:00:00Z"):
    return Trace(relay, queue_id, arrival, f"{name}@receiver.example")


alice = trace("A1", "alice")
bob = trace("A1", "bob")
carol = trace("B2", "carol")
dan = trace("C3", "dan")
eve = trace("D4", "eve")
farah = trace("E5", "farah")
gina = trace("F6", "gina")
hana = trace("G7", "hana")

# Fixture records correspond to distinct stages. Quarantine and mailbox
# records have already been corroborated and mapped to their relay trace.
observed = [
    Observation(alice, 0, "rcpt", 250),
    Observation(bob, 0, "rcpt", 550),
    Observation(alice, 1, "final_reply", 451),
    Observation(alice, 17, "final_reply", 250),
    Observation(carol, 0, "rcpt", 250),
    Observation(dan, 0, "final_reply_missing"),
    Observation(eve, 0, "final_reply", 250),
    Observation(eve, 2, "trusted_quarantine_record"),
    Observation(farah, 0, "rcpt", 250),
    Observation(farah, 1, "final_reply", 554),
    Observation(gina, 0, "final_reply", 250),
    Observation(gina, 2, "trusted_mailbox_record"),
    Observation(hana, 0, "rcpt", 451),
    # These matching queue IDs refer to other trace instances.
    Observation(trace("C3", "dan", relay="mx-b.example"), 1, "final_reply", 250),
    Observation(trace("C3", "dan", arrival="2026-11-20T12:00:00Z"), 1, "final_reply", 250),
]

checks = [
    (alice, "NEXT_HOP_ACCEPTED"),
    (bob, "PERMANENT_REPLY"),
    (carol, "RECIPIENT_ACCEPTED_ONLY"),
    (dan, "HANDOFF_UNCONFIRMED"),
    (eve, "QUARANTINED"),
    (farah, "PERMANENT_REPLY"),
    (gina, "MAILBOX_DELIVERED"),
    (hana, "TEMPORARY_REPLY"),
    (trace("A1", "unlisted"), "NO_MATCHING_EVIDENCE"),
]

if __name__ == "__main__":
    for key, expected in checks:
        actual = classify(observed, key)
        if actual != expected:
            raise AssertionError(f"{key}: expected {expected}, saw {actual}")
        print(f"{key.queue_id} {key.recipient}: {actual}")
    print(f"{len(checks)} synthetic checks passed.")
