import time
from config.security_baseline import SECURITY_BASELINE
from parsers.packet_parser import PacketParser
from core.normalizer import SignalNormalizer
from core.session_manager import SessionManager
from analysis.rule_engine import RuleEngine
from analysis.risk_engine import RiskEngine
from analysis.confidence_engine import ConfidenceEngine
from reports.report_builder import ReportBuilder
from reports.quality import qualify_session, apply_report_quality


class SecurityEngine:
    def __init__(self, max_sessions=512, idle_timeout=300):
        self.packet_parser = PacketParser()
        self.normalizer = SignalNormalizer()
        self.rule_engine = RuleEngine()
        self.risk_engine = RiskEngine()
        self.confidence_engine = ConfidenceEngine()
        self.report_builder = ReportBuilder()
        self.max_sessions, self.idle_timeout = max_sessions, idle_timeout
        self.reset()

    def reset(self):
        self.session_manager = SessionManager(self.max_sessions, self.idle_timeout)
        self.packet_count = self.security_packets = 0
        self.last_packet_at = None

    def ingest(self, packet):
        self.packet_count += 1
        signals = self.packet_parser.parse(packet, packet_number=self.packet_count)
        if signals:
            self.security_packets += 1
            self.last_packet_at = signals[0].timestamp
            self.session_manager.ingest(signals, now=time.monotonic())

    def snapshot(self, source_type="unknown"):
        self.session_manager.expire(time.monotonic())
        sessions, findings = [], []
        all_signals = []
        for session in self.session_manager.sessions.values():
            evidence = session.evidence()
            all_signals.extend(evidence)
            session_findings = []
            common = [s for s in evidence if s.scope == "observed"]
            # Evaluate offers independently. They never describe an established SA.
            for scope in ("observed", "offered", "selected"):
                scoped = [s for s in evidence if s.scope == scope]
                if not scoped:
                    continue
                normalized = self.normalizer.normalize(scoped)
                if scope == "selected":
                    for s in common:
                        if s.name == "ike_version":
                            normalized["ike_version"] = s.value
                result = self.rule_engine.evaluate(normalized, scope=scope)
                for f in result:
                    if scope == "selected" and f["parameter"] in ("compliance", "ike_version"):
                        continue
                    if scope == "offered" and f["status"] in ("UNKNOWN", "PASS", "NOT_APPLICABLE"):
                        continue
                    matching = [s for s in scoped if s.name == f["parameter"]
                                and (s.value == f["value"] or f["value"] == "AEAD")]
                    if f["parameter"] == "integrity" and f["value"] == "AEAD":
                        matching = [s for s in scoped if s.name == "encryption"]
                    if scope == "selected" and f["parameter"] == "ike_version":
                        matching = [s for s in common if s.name == "ike_version"]
                    f.update(session_id=session.session_id,
                        finding_id=f"{session.session_id}/{scope}/{f['rule_id']}/{f['value']}",
                        evidence=[s.to_dict() for s in matching[:3]],
                        evidence_confidence="DIRECT_OBSERVATION" if matching else "UNAVAILABLE")
                    session_findings.append(f)
            # Do not report a field as missing when another scope provided evidence.
            resolved = {f["parameter"] for f in session_findings
                        if f["scope"] != "offered" and f["status"] in ("PASS", "FAIL", "NOT_APPLICABLE")}
            session_findings = [f for f in session_findings
                                if not (f["status"] == "UNKNOWN" and f["value"] is None and f["parameter"] in resolved)]
            normalized = self.normalizer.normalize(evidence)
            confidence = self.confidence_engine.calculate(normalized, session_findings)
            risk = self.risk_engine.calculate(session_findings)
            if session.truncated:
                risk["security_score"] = None
                confidence["evidence_confidence"] = "LIMITED"
            offered_risk = self.risk_engine.calculate([
                {**f, "scope": "observed"} for f in session_findings if f["scope"] == "offered"])
            details = session.to_dict()
            details.update(offered_policy_risk=offered_risk,
                observation_scope="Individual SA; IKE and ESP are not linked without gateway evidence")
            details.update(signals=normalized, findings=session_findings, risk=risk, confidence=confidence,
                assessment_status="PROVISIONAL" if risk["score"] is not None else "UNKNOWN")
            qualify_session(details)
            sessions.append(details)
            findings.extend(session_findings)
        normalized = self.normalizer.normalize(all_signals)
        risk = self.risk_engine.calculate(findings)
        if any(s["evidence_truncated"] for s in sessions):
            risk["security_score"] = None
        coverage = min((s["confidence"]["coverage"] for s in sessions), default=0)
        confidence = {"score": coverage, "coverage": coverage,
                      "meaning": "Minimum supported-check coverage across retained SAs; see each SA for details."}
        report = self.report_builder.build(self.packet_count, self.security_packets, normalized,
            findings, risk, confidence, sessions, source_type)
        report["metadata"].update(policy_name=SECURITY_BASELINE["policy_name"],
            policy_version=SECURITY_BASELINE["policy_version"],
            evidence_truncated=any(s["evidence_truncated"] for s in sessions),
            crypto_summary_scope="Observed inventory across retained SAs, not a negotiated suite")
        report["traffic"].update(last_packet_at=self.last_packet_at,
            retained_sessions=len(sessions), evicted_sessions=self.session_manager.evicted,
            capture_drops=None, scope="retained sessions; packet counters cover the entire run")
        report["summary"].update(assessment_coverage=coverage, assessment_status="PROVISIONAL" if risk["score"] is not None else "UNKNOWN")
        return apply_report_quality(report)

    def analyze(self, packets, source_type="unknown", on_update=None, update_interval=2):
        if update_interval <= 0:
            raise ValueError("Update interval must be positive")
        self.reset()
        last_update = 0
        try:
            for packet in packets:
                # Live sources yield None heartbeats so idle periods also publish status.
                if packet is not None:
                    self.ingest(packet)
                now = time.monotonic()
                if on_update and now-last_update >= update_interval:
                    on_update(self.snapshot(source_type))
                    last_update = now
        except KeyboardInterrupt:
            report = self.snapshot(source_type)
            report["metadata"]["stopped_by_user"] = True
            return report
        return self.snapshot(source_type)
