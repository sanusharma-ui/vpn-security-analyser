from core.session import VPNSession
from core.signal import SecuritySignal


class SessionManager:

    def __init__(self):
        self.sessions = {}

    def ingest(self, signals):
        generated_signals = []

        for signal in signals:
            session_id = signal.session_id
            if not session_id:
                continue

            if session_id not in self.sessions:
                self.sessions[session_id] = VPNSession(session_id=session_id)

            session = self.sessions[session_id]
            extra_events = session.add_signal(signal.name, signal.value)
            for event_name, event_val in extra_events:
                generated_signals.append(
                    SecuritySignal(
                        name=event_name,
                        value=event_val,
                        source="session",
                        packet_number=signal.packet_number,
                        session_id=session_id,
                        category="vulnerability"
                    )
                )

        return generated_signals

    def get_sessions(self):
        return [
            session.to_dict()
            for session in self.sessions.values()
        ]