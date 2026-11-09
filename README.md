# CyberShield 2.1

Defensive security analytics prototype built with Streamlit, Pandas and Plotly.

## Improvements
- Redesigned Security Overview dashboard.
- Correlation groups based on source IP and time proximity.
- Rolling-window failed-login correlation.
- Event Investigation with filters and evidence.
- Incident Correlation view with related events.
- Event activity timeline and risk distribution.
- Downloadable event and incident CSV reports.

## Deploy
Replace `app.py` and `requirements.txt` in the existing GitHub repository. Keep the Streamlit app connected to that repository and set the main file to `app.py`.

## CSV format
Required: `timestamp`, `source_ip`, `event_type`
Optional: `failed_logins`, `bytes_out`, `destination_port`

## Scope
Educational defensive prototype. It analyses supplied records; it does not monitor live networks, scan, block, or automatically respond. Risk scores and correlation groups are triage aids, not proof of malicious activity.
