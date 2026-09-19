from collections import OrderedDict
from core.session import VPNSession


class SessionManager:
    def __init__(self, max_sessions=512, idle_timeout=300):
        if max_sessions < 1 or idle_timeout <= 0:
            raise ValueError("Session limits must be positive")
        self.sessions = OrderedDict()
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self.evicted = 0

    def expire(self, now):
        for key, session in list(self.sessions.items()):
            if now-session.last_seen > self.idle_timeout:
                del self.sessions[key]
                self.evicted += 1

    def ingest(self, signals, now=0):
        self.expire(now)
        for signal in signals:
            key = signal.session_id or f"unattributed:{signal.packet_number}"
            if key.startswith("ike:") and "/" in key:
                base, responder = key.rsplit("/", 1)
                pending = base + "/0"
                if responder != "0" and key not in self.sessions and pending in self.sessions:
                    session = self.sessions.pop(pending)
                    session.session_id = key
                    for sample in session.evidence():
                        sample.session_id = key
                    self.sessions[key] = session
                elif responder == "0" and key not in self.sessions:
                    candidates = [k for k in self.sessions if k.rsplit("/", 1)[0] == base]
                    if len(candidates) == 1:
                        key = candidates[0]
                signal.session_id = key
            if key not in self.sessions:
                if len(self.sessions) >= self.max_sessions:
                    self.sessions.popitem(last=False)
                    self.evicted += 1
                self.sessions[key] = VPNSession(key)
            session = self.sessions[key]
            session.last_seen = now
            session.ingest(signal)
            self.sessions.move_to_end(key)
        return []

    def get_sessions(self):
        return [session.to_dict() for session in self.sessions.values()]
