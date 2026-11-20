# ZTShield — Test and Validation Report

**Project:** ZTShield — Zero-Trust Network Defense & Attack Simulation Platform
**Report date:** 20 November 2026
**Environment:** Local development on Windows

## 1. Purpose

This report records the software testing and validation performed on ZTShield. It distinguishes verified results from tests that remain pending.

## 2. Test Environment

- Operating system: Windows
- Backend: Python 3.13, FastAPI, SQLAlchemy
- Database: SQLite
- Frontend: React, TypeScript and Vite
- Network security telemetry: Suricata 8.0.7
- Firewall integration: pfSense 2.9.0
- Test framework: pytest

## 3. Backend Testing

The backend regression suite was executed using pytest.

**Result: 66 tests passed in 6.77 seconds.**

The test suite includes API tests and tests for the intelligence modules:

- Attack detection
- Event correlation
- Risk scoring
- Incident orchestration

The passing test result confirms that the implemented test cases completed successfully in the tested environment.

## 4. Frontend Build Validation

The frontend production build was executed using:

`npm.cmd run build`

Results:

- TypeScript compilation: Passed
- Vite production build: Passed
- Modules transformed: 1,934
- JavaScript bundle: 250.03 kB
- CSS bundle: 19.39 kB

No build errors were reported.

## 5. API Authentication Testing

The Suricata ingestion endpoint was tested with different authentication conditions.

| Test case | Expected result | Observed result |
|---|---|---|
| Missing authentication token | HTTP 401 | Passed |
| Invalid authentication token | HTTP 401 | Passed |
| Valid authentication token | Successful ingestion | HTTP 201 |

The API uses token-based authentication for telemetry ingestion.

## 6. Suricata EVE Watcher Validation

An isolated EVE JSON test event was created to validate the watcher without modifying the existing live Suricata logs.

The watcher was executed with live capture mode and the configured backend API endpoint.

Observed result:

`INGESTED SURICATA-7EAF04E09E3F - ZTShield Watcher Authentication Validation`

The watcher successfully authenticated and submitted the event to the backend.

## 7. Database Persistence Validation

The ingested event was queried directly from the SQLite alerts table.

Verified event details:

| Field | Value |
|---|---|
| Event ID | SURICATA-7EAF04E09E3F |
| Source type | suricata_live |
| Title | ZTShield Watcher Authentication Validation |
| Severity | High |
| Source IP | 192.168.40.100 |
| Destination | 192.168.30.100:22 |
| Protocol | TCP |
| Zone | MANAGEMENT |

The database query returned the expected event and telemetry fields.

## 8. Dashboard Validation

The Security Alerts dashboard was refreshed after ingestion.

Visual verification confirmed:

- The newly ingested Suricata event appeared in the alerts table.
- The event displayed High severity.
- Source and destination details were displayed.
- Protocol and source classification were visible.
- Corrected arrow, separator and dash characters rendered properly after the frontend encoding fix.

## 9. Test Summary

| Validation area | Result |
|---|---|
| Backend regression tests | 66 passed |
| Frontend production build | Passed |
| Missing-token rejection | Passed |
| Invalid-token rejection | Passed |
| Authenticated API ingestion | Passed |
| EVE watcher ingestion | Passed |
| SQLite persistence | Passed |
| Dashboard display | Passed |
| Frontend character encoding | Passed |

## 10. Pending Validation

The following work should not be considered fully validated based on the evidence recorded in this report:

- Final network segmentation regression across all lab zones.
- Complete DMZ server connectivity validation.
- Final end-to-end testing across all intended network components.
- Formal performance and throughput benchmarking.
- Quantitative detection accuracy evaluation using a labelled test dataset.

These items require additional testing and evidence before they can be reported as completed.

## 11. Conclusion

The completed tests demonstrate that the ZTShield backend regression suite, frontend production build, authenticated Suricata ingestion workflow, SQLite persistence and dashboard presentation are functioning successfully in the tested local environment.

Further network-lab validation and quantitative performance evaluation remain necessary to establish the complete operational coverage of the platform.
