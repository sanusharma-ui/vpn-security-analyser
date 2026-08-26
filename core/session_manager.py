from core.session import VPNSession


class SessionManager:

    def __init__(self):

        self.sessions = {}

    def ingest(self, signals):

        for signal in signals:

            session_id = signal.session_id

            if not session_id:
                continue

            if session_id not in self.sessions:

                self.sessions[
                    session_id
                ] = VPNSession(
                    session_id=session_id
                )

            self.sessions[
                session_id
            ].add_signal(
                signal.name,
                signal.value
            )

    def get_sessions(self):

        return [
            session.to_dict()
            for session
            in self.sessions.values()
        ]