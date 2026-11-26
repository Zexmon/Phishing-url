# Project memory

## Product intent & audience

- Phishing URL detection tool; project report is the source spec (report file was a `.docx` that could not be parsed in this environment).
- Likely target: a web app where users paste a URL and receive a phishing/safe prediction with an explanation/breakdown.
- Audience likely technical/academic (project report context) and/or end users checking URLs.

## Brand personality & voice

- Clear, educational, and trustworthy; explains detection factors rather than giving only a binary verdict.
- Practical and transparent about methodology and limitations.

## Visual design & UX direction

- Expected core flow: URL input → analysis → result with feature-level breakdown (which flags triggered).
- Preference (proposed): in-browser detection, no backend model dependency.
- No concrete visual tokens (color, typography, layout) decided yet.

## Decisions, constraints & rationale

- `.docx` report could not be read; filename indicates phishing URL detection project ("Phishing_URL_Detection_Project_Report_Updated").
- Assistant proposed a heuristic approach: ~15 common phishing indicators (URL length, `@`, IP in URL, HTTPS status, subdomain count, suspicious characters, etc.) scored in-browser.
- Awaiting user confirmation on app type and detection approach before building.

## Open questions & assumptions

- App type: single-URL checker vs. dashboard with history/batch vs. demo/landing page?
- Detection method: client-side heuristics, ML model with specific features, rules-based scoring, or external API (Google Safe Browsing, PhishTank)?
- Exact features/attributes used by the report's model.
- Algorithm specified (Random Forest, Logistic Regression, etc.)?
- Dataset details and target metrics/accuracy to display.
- Does user need backend, or is frontend-only acceptable?
- User has not yet pasted report content or selected a direction.