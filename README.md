\# PhishGuard 🔐



PhishGuard is a rule-based phishing URL risk analyzer built using Python and Flask.



It analyzes a URL using multiple security-related characteristics and generates a risk score to classify the URL as:



\- 🟢 Likely Safe

\- 🟡 Suspicious

\- 🔴 High Risk



\## Features



\- URL risk scoring

\- HTTPS verification

\- IP address detection

\- Long URL detection

\- URL shortener detection

\- Suspicious keyword detection

\- Punycode detection

\- Multiple subdomain detection

\- `@` symbol detection

\- Sensitive path detection

\- SQLite-based scan history

\- Dashboard with scan statistics

\- Visual risk meter

\- Responsive web interface



\## Technologies Used



\- Python

\- Flask

\- HTML

\- CSS

\- SQLite

\- Jinja2



\## How It Works



1\. The user enters a URL.

2\. PhishGuard analyzes different characteristics of the URL.

3\. Each suspicious characteristic contributes to a risk score.

4\. The final score is used to classify the URL.

5\. The scan result is stored in an SQLite database.

6\. Previous scans and statistics are displayed on the dashboard.



\## Risk Classification



| Score | Classification |

|---|---|

| 0–19 | Likely Safe |

| 20–49 | Suspicious |

| 50–100 | High Risk |



\## Project Structure



```text

PhishGuard/

│

├── app.py

├── detector.py

├── requirements.txt

├── .gitignore

├── templates/

│   └── index.html

└── README.md

