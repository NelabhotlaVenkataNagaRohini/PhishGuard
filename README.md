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

├── app.py

├── detector.py

├── requirements.txt

├── .gitignore

├── README.md

├── templates/

│   └── index.html

└── docs/

&#x20;   ├── architecture.png

&#x20;   ├── flowchart.png

&#x20;   ├── dashboard.png

&#x20;   ├── high-risk.png

&#x20;   └── suspicious.png

```



\## Project Architecture



!\[PhishGuard Architecture](docs/architecture.png)



\## Project Flowchart



!\[PhishGuard Flowchart](docs/flowchart.png)



\## Screenshots



\### Dashboard



!\[PhishGuard Dashboard](docs/dashboard.png)



\### High Risk URL Detection



!\[High Risk Detection](docs/high-risk.png)



\### Suspicious URL Detection



!\[Suspicious URL Detection](docs/suspicious.png)



\## Installation



Clone the repository:



```bash

git clone https://github.com/NelabhotlaVenkataNagaRohini/PhishGuard.git

cd PhishGuard

```



Create a virtual environment:



```bash

python -m venv venv

```



Activate it on Windows:



```bash

venv\\Scripts\\activate

```



Install dependencies:



```bash

pip install -r requirements.txt

```



Run the application:



```bash

python app.py

```



Open the application in your browser:



```text

http://127.0.0.1:5000

```



\## Example



Example URL:



```text

http://192.168.1.10/login

```



The application detects multiple suspicious characteristics such as:



\- HTTP instead of HTTPS

\- IP address in the URL

\- Suspicious login keyword



and calculates a higher risk score.



\## Disclaimer



PhishGuard is a rule-based URL analysis tool intended for educational and demonstration purposes. Its result does not guarantee that a website is safe or malicious. It evaluates URL characteristics using predefined rules and does not perform live website verification.



\## Future Enhancements



\- Machine learning-based detection

\- Threat intelligence API integration

\- Domain reputation checking

\- WHOIS information

\- Browser extension

\- More advanced URL analysis

