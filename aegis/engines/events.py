"""Agent event stream — the Strix-style live transcript Aegis agents emit.

Each agent turn produces typed events: assistant prose, private ``think`` notes,
tool calls *with arguments*, tool outputs, typed decisions, subagent spawns,
inter-agent messages, filed findings, and finish. The Orchestrator hands the
engine an :class:`EventSink` that buffers the stream and, when a path is given,
appends each event to a JSONL file so the dashboard can **tail it live** — no
server beyond the local dev server, no telemetry.

Clean-room: this reproduces the *shape* of Strix's per-agent event/message
stream (``strix/interface/tui/live_view.py``: assistant messages, tool_call and
tool_call_output items, the ``think`` tool), in original code. Offline, a
deterministic scripted agent emits the same event types so a run and the whole
test suite work with no model and no network.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# The event vocabulary the dashboard transcript understands.
EVENT_TYPES = (
    "spawn",        # a (sub)agent was created: {role, task, parent_id}
    "status",       # agent status changed: {status}
    "assistant",    # the model's prose for this turn: {text}
    "think",        # a private chain-of-thought note: {text}
    "tool_call",    # a tool invoked with arguments: {tool, args}
    "tool_output",  # that tool's result: {tool, status, summary, count}
    "decision",     # a typed decision through the router: {kind, outcome, probability, backend}
    "message",      # inter-agent message: {to|from, text}
    "finding",      # a filed finding: {id, title, severity, exploitable}
    "finish",       # the agent completed: {summary}
)


@dataclass
class EventSink:
    """Collects agent events in order; optionally streams them to JSONL.

    Thread-safe: engines may run in parallel. ``emit`` returns the event's
    sequence number so callers can correlate (e.g. a tool_output to its call).
    """

    path: Optional[Path] = None
    #: Optional live subscriber, invoked with each event *after* it is recorded
    #: (under the lock). A single in-process observer — e.g. the interactive
    #: shell's terminal renderer. It must be cheap, non-reentrant (never call
    #: back into ``emit``) and must not raise; ``emit`` guards it regardless.
    on_emit: Optional[Callable[[dict], None]] = None
    _events: List[dict] = field(default_factory=list)
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            try:  # start a fresh stream each run
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text("", encoding="utf-8")
            except OSError:
                pass

    def emit(self, agent_id: str, type: str, **data) -> int:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "agent_id": agent_id, "type": type, **data}
            self._events.append(event)
            if self.path is not None:
                try:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(event) + "\n")
                except OSError:
                    pass
            if self.on_emit is not None:
                # A subscriber error must never break the agent loop or the
                # JSONL write (the audit trail), so swallow anything it raises.
                try:
                    self.on_emit(event)
                except Exception:  # noqa: BLE001 - renderer must not be fatal
                    pass
            return self._seq

    @property
    def events(self) -> List[dict]:
        with self._lock:
            return list(self._events)


class NullSink:
    """A sink that records nothing — the default when transcripts are off."""

    events: List[dict] = []

    def emit(self, *args, **kwargs) -> int:  # noqa: D401 - no-op
        return 0


__all__ = ["EventSink", "NullSink", "EVENT_TYPES"]
