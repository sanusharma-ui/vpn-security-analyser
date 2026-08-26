# VPN Security Analyzer

VPN Security Analyzer is a Python-based tool for analyzing IPsec VPN traffic from PCAP and PCAPNG files. It extracts VPN and IKE security signals, evaluates them against a configurable security baseline, and produces a structured security report.

## Current Status

The project currently provides a working PCAP analysis pipeline. It can:

- Read packets from PCAP and PCAPNG files with PyShark.
- Detect and normalize relevant IPsec and IKE signals.
- Track analysis sessions and packet-processing state.
- Evaluate IKE versions, encryption algorithms, key lengths, PRFs, and Diffie-Hellman groups.
- Generate findings with rule IDs, severity levels, values, and explanatory messages.
- Calculate a risk score, risk level, security score, and analysis confidence.
- Build JSON-compatible security reports.
- Support live and PCAP-based data sources through the source abstraction.

The core workflow is implemented and can be executed from the command line. The repository is still under active development, and the current test files do not yet contain automated test cases.

## Requirements

- Python 3.10 or newer
- Wireshark/TShark installed and available on `PATH` for PyShark packet parsing

## Setup

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Analyze a PCAP file:

```powershell
python app.py data/pcaps/test_vpn.pcap
```

Save the generated JSON report to a file:

```powershell
python app.py data/pcaps/test_vpn.pcap --output data/reports/report.json
```

## Project Structure

```text
ai/         AI explanation and model integration
analysis/   Rules, risk scoring, confidence, and feature extraction
api/        API routes and schemas
config/     Security baseline configuration
core/       Analysis engine, sessions, signals, and normalization
parsers/    IKE, IPsec, and packet parsing
reports/    Report construction and report schemas
sources/    PCAP and live packet sources
data/       PCAP files, models, and generated reports
tests/      Test suite location
```

## Security Baseline

The baseline is defined in `config/security_baseline.py`. It contains preferred and legacy IKE versions, encryption classifications, minimum key length, PRF classifications, and Diffie-Hellman group classifications. Adjust this file when the organization needs a different policy baseline.

## Roadmap

Future versions will make the analyzer stronger and more production-ready by adding:

- Comprehensive automated unit and integration tests.
- More complete IKEv1/IKEv2 and IPsec proposal parsing.
- Better handling of fragmented, encrypted, and incomplete captures.
- More robust confidence scoring and evidence tracking.
- Expanded security rules and organization-specific policy profiles.
- Improved live capture support and API integration.
- Historical comparison, trend analysis, and alerting.
- Stronger AI-assisted explanations with auditable evidence.
- Performance improvements for large PCAP files.

The goal is to evolve this project into a stronger, more accurate, and more reliable VPN security assessment platform.

## License

No license has been specified yet.
