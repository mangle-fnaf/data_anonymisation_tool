# Data Anonymisation Tool

This project is a practical data anonymisation tool designed to transform sensitive information into safe, non-identifiable formats. It demonstrates secure data handling, hashing techniques, and structured anonymisation workflows suitable for environments where privacy, compliance, and controlled data sharing are essential.

## Overview
The tool anonymises user-provided data using hashing, masking, and structured transformation rules. It provides a simple way to protect identifiable information before storage, analysis, or transfer. This project reflects real-world data protection practices used in cybersecurity, healthcare, and governance environments.

## Features
- SHA-256 hashing for irreversible anonymisation  
- Masking of identifiable fields  
- Clear separation between raw and anonymised data  
- Simple CLI interface for demonstration and testing  
- Consistent anonymisation rules for predictable output  

## Why I Built This
I created this tool to explore practical data protection techniques and strengthen my understanding of secure data handling. It allowed me to apply cybersecurity concepts such as hashing, privacy-by-design, and safe transformation of user data. This project also supports my interest in data governance and secure sandbox environments.

## How It Works
1. User enters sensitive information  
2. The tool applies hashing or masking rules  
3. An anonymised version of the data is generated  
4. Output is displayed clearly for comparison  

## Example Output
Input: John Smith
Hashed: 3a7bd3e2360a3d...
Masked: J*** S****


## How to Run
1. Clone the repository  
2. Open the project folder  
3. Run the script using Python  
4. Follow the on-screen prompts to enter data  

## Tech Stack
- Python  
- Hashlib  
- Basic CLI interface  

## What I Learned
- How hashing protects sensitive information  
- How to design simple anonymisation rules  
- How to structure secure data workflows  
- How to evaluate risks and limitations in anonymisation  
- How anonymisation supports safe testing environments  

## Future Improvements
- Add multiple anonymisation profiles  
- Add export options for anonymised datasets  
- Add a GUI version for easier use  
- Integrate additional hashing algorithms  
- Add logging and audit trails for compliance  

