- Data Anonymisation & Privacy Tool - 
This project is a small Python application I built to practise secure data handling, anonymisation techniques, and basic privacy risk assessment. It takes a CSV file containing employee data and applies different anonymisation methods depending on the configuration set in config.json.

The aim of the project is to understand how organisations protect sensitive information before using data for testing, analysis, or development.

- Features - 

~ Anonymisation Methods ~
The tool supports several anonymisation techniques:
Name → Redacted
Email → SHA‑256 hash
EmployeeID → Tokenised (keeps uniqueness without revealing identity)
Salary → Encrypted using Fernet (AES‑based encryption)

These methods can be changed or extended through config.json.

~ Synthetic Data ~
If real data isn’t required, the tool can generate synthetic employee records. This is controlled by:
"generate_synthetic": true
Synthetic data allows safe testing without exposing real personal information.

~ Risk Scoring ~
The tool calculates a simple privacy risk score before and after anonymisation.
This is not a full GDPR assessment, but it provides a quick indication of how much risk is reduced when identifiers are removed or encrypted.

~ Privacy Report 
Each run produces a privacy_report.txt summarising:
What was anonymised
Why those methods were chosen
Risk scoring
Remaining considerations
The project owner’s name
This simulates a basic privacy workflow.

~ CLI Menu ~
A simple command‑line menu is included to make the tool easier to use:
1. Anonymise real CSV
2. Generate synthetic data
3. View risk score only
4. Exit

~ Configuration ~
The anonymisation behaviour is controlled through config.json.
Example:

{
    "project_owner": "Maliyka",
    "generate_synthetic": true,
    "fields": {
        "Name": "redact",
        "Email": "hash",
        "EmployeeID": "tokenise",
        "Salary": "encrypt"
    }
}

This makes the tool flexible and easy to adjust without modifying the main script.

- Project Structure -

Data_anonymisation_tool/
│
├── data/
│   └── sample.csv
│
├── output/
│   └── anonymised.csv
│
├── reports/
│   ├── anonymisation.log
│   └── privacy_report.txt
│
├── config.json
├── anonymisation.py
└── encryption.key

- Purpose -
I built this project to learn and practise:
Anonymisation techniques
Hashing vs encryption
Tokenisation
Logging and audit trails
Basic privacy risk scoring
Secure data‑handling workflows

It helped me understand how sensitive data can be protected before being used in non‑production environments.

- Future Improvements -
Possible additions:
GUI version
More anonymisation options
Regex‑based masking
Exporting reports in different formats
More detailed risk modelling

- Author - 
Maliyka  
Cybersecurity student focusing on secure coding, privacy engineering, and data protection.