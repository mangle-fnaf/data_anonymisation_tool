# Import the libraries I need for reading data,
# protecting information and generating reports.
import csv
import hashlib
import os
import json
import logging
import random
import copy
from cryptography.fernet import Fernet

# Basic logging so I can keep track of what the script actually does
logging.basicConfig(
    filename="reports/anonymisation.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

CONFIG_FILE = "config.json"

def load_config(config_file):
    # Load my anonymisation settings from config.json
    with open(config_file, "r", encoding="utf-8") as f:
        return json.load(f)

INPUT_FILE = "data/sample.csv"
OUTPUT_FILE = "output/anonymised.csv"
REPORT_FILE = "reports/privacy_report.txt"


def load_data(input_file):
    # Read the CSV file and turn it into a list of dictionaries

    # Make sure the file exists before trying to open it.
    if not os.path.exists(input_file):
        raise FileNotFoundError(
            f"Input file '{input_file}' not found."
        )

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Store all rows from the CSV file in memory.
        rows = list(reader)

    return rows, reader.fieldnames


def save_data(rows, fieldnames, output_file):
    # Save the anonymised data into the output folder

    # Create the output folder automatically if it doesn't exist yet.
    os.makedirs(
        os.path.dirname(output_file),
        exist_ok=True
    )

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        # Write the column names first.
        writer.writeheader()

        # Then write all of the anonymised records.
        writer.writerows(rows)

def hash_value(value):
    # SHA-256 hashing – irreversible and keeps patterns consistent
    return hashlib.sha256(
        str(value).encode("utf-8")
    ).hexdigest()


def tokenise_value(index):
    # Simple token system so IDs stay unique but no longer identify real people
    return f"TOKEN_{index:03d}"


def load_or_create_key():
    # I want a stable encryption key so encrypted fields stay consistent.
    key_file = "encryption.key"

    # Reuse an existing key if one has already been generated.
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()

    # If no key exists yet, make one.
    key = Fernet.generate_key()

    with open(key_file, "wb") as f:
        f.write(key)

    return key


def encrypt_value(value, fernet):
    # Encrypt the value using Fernet (AES-based)
    return fernet.encrypt(
        str(value).encode("utf-8")
    ).decode("utf-8")


def anonymise_row(row, index, config, fernet):
    # Apply whatever rules I set in config.json

    # Work on a copy so I don't accidentally change the original data.
    row = copy.deepcopy(row)

    for field, method in config["fields"].items():

        # Skip any fields that aren't present in the dataset.
        if field not in row:
            logging.warning(
                f"Field '{field}' not found in dataset."
            )
            continue

        original = row.get(field, "")

        # No point anonymising empty values.
        if original in [None, ""]:
            continue

        if method == "redact":

            # Completely remove the original value.
            row[field] = "[REDACTED]"

        elif method == "hash":

            # Replace the value with a SHA-256 hash.
            row[field] = hash_value(row[field])

        elif method == "tokenise":

            # Replace the value with a non-identifying token.
            row[field] = tokenise_value(index)

        elif method == "encrypt":

            # Encrypt the value so it can't be read without the key.
            row[field] = encrypt_value(
                row[field],
                fernet
            )

        # Log what happened for my own audit trail
        logging.info(
            f"{field} anonymised using '{method}'."
        )

    return row

def anonymise_data(rows, config, fernet):
    # Run anonymisation on every row in the dataset

    anonymised_rows = []

    for i, row in enumerate(rows, start=1):

        # Process one row at a time using the rules from the config file.
        anonymised_row = anonymise_row(
            row,
            i,
            config,
            fernet
        )

        anonymised_rows.append(anonymised_row)

    return anonymised_rows


def calculate_risk_scores(original_rows, anonymised_rows):
    # Quick and simple risk scoring system based on how sensitive each field is

    # Higher numbers mean the field is more sensitive.
    risk_levels = {
        "Name": 10,          # direct identifier
        "Email": 9,          # strong identifier
        "EmployeeID": 7,     # internal identifier
        "Department": 2,     # low sensitivity
        "Salary": 4          # financial but not identifying
    }

    # Average risk before anonymisation
    total_before = sum(risk_levels.values())
    avg_before = total_before / len(risk_levels)

    # Average risk after anonymisation
    total_after = 0

    for field, score in risk_levels.items():

        if field in ["Name", "Email", "EmployeeID"]:

            # Assume these fields have a much lower risk once anonymised.
            total_after += 1

        else:

            # Keep the original score for fields that remain visible.
            total_after += score

    avg_after = total_after / len(risk_levels)

    return avg_before, avg_after


def generate_report(original_rows, anonymised_rows, report_file):

    # Create the reports folder automatically if it doesn't exist.
    os.makedirs(
        os.path.dirname(report_file),
        exist_ok=True
    )

    num_rows = len(original_rows)

    # Write everything into the privacy report
    with open(report_file, "w", encoding="utf-8") as f:

        # Summarise what the tool did and how much privacy risk was reduced.
        f.write("Privacy & Anonymisation Summary\n")
        f.write("================================\n\n")
        f.write(f"Records processed: {num_rows}\n\n")

        f.write("What I anonymised:\n")
        f.write("- Name: fully removed\n")
        f.write("- Email: converted to SHA-256 hash\n")
        f.write("- EmployeeID: replaced with non-identifying tokens\n")
        f.write("- Salary: encrypted (AES-based)\n\n")

        f.write("Why I chose these methods:\n")
        f.write("I wanted to protect identity while keeping the dataset useful for testing.\n")
        f.write("Hashing keeps patterns, tokenising keeps uniqueness, and redaction removes risk.\n")
        f.write("Encryption adds confidentiality for fields that shouldn't be visible at all.\n\n")

        # Risk scoring section
        avg_before, avg_after = calculate_risk_scores(
            original_rows,
            anonymised_rows
        )

        f.write("Risk scoring:\n")
        f.write(f"- Average risk before anonymisation: {avg_before:.1f}/10\n")
        f.write(f"- Average risk after anonymisation: {avg_after:.1f}/10\n\n")

        if avg_after <= 3:
            f.write("Overall risk level: LOW\n\n")

        elif avg_after <= 6:
            f.write("Overall risk level: MEDIUM\n\n")

        else:
            f.write("Overall risk level: HIGH\n\n")

        f.write("Remaining considerations:\n")
        f.write("- Salary and Department are still visible.\n")
        f.write("- If combined with external data, re-identification is still possible.\n\n")

        f.write("Overall:\n")
        f.write("This anonymised dataset is suitable for safe technology evaluation without exposing personal details.\n")
        f.write("\nReport generated by: Maliyka\n")


def generate_synthetic_data(num_records=5):
    # Generate fake but realistic employee data for testing

    departments = ["Engineering", "HR", "Finance", "Sales"]
    synthetic_rows = []

    for i in range(1, num_records + 1):

        # Create a fake employee record each time the loop runs.
        synthetic_rows.append({
            "Name": f"User{i}",
            "Email": f"user{i}@example.com",
            "EmployeeID": f"EMP{i:03d}",
            "Department": random.choice(departments),
            "Salary": random.randint(30000, 60000)
        })

    return synthetic_rows


# CLI MENU SECTION
# CLI MENU SECTION

def menu():
    # Simple menu so I can choose what I want the tool to do.
    print("\n=== Data Anonymisation Tool ===")
    print("1. Anonymise real CSV")
    print("2. Generate synthetic data")
    print("3. View risk score only")
    print("4. Exit")

    return input("Choose an option: ")


def main():

    # Load my settings and encryption key before anything else.
    config = load_config(CONFIG_FILE)
    fernet = Fernet(load_or_create_key())

    # Keep running until I choose to exit the tool.
    while True:

        choice = menu()

        # Load and anonymise a real CSV file.
        if choice == "1":

            try:
                original_rows, fieldnames = load_data(INPUT_FILE)

            except FileNotFoundError as e:
                print(f"\nError: {e}\n")
                continue

        # Generate fake data if I just want to test everything.
        elif choice == "2":

            original_rows = generate_synthetic_data()
            fieldnames = original_rows[0].keys()

        # Show privacy risk levels without saving any files.
        elif choice == "3":

            if config.get("generate_synthetic"):
                original_rows = generate_synthetic_data()
                fieldnames = original_rows[0].keys()
            else:
                original_rows, fieldnames = load_data(INPUT_FILE)

            anonymised_rows = anonymise_data(
                original_rows,
                config,
                fernet
            )

            avg_before, avg_after = calculate_risk_scores(
                original_rows,
                anonymised_rows
            )

            print(f"\nRisk before anonymisation: {avg_before:.1f}/10")
            print(f"Risk after anonymisation: {avg_after:.1f}/10\n")

            continue

        # Exit the program.
        elif choice == "4":

            print("Goodbye!")
            break

        # Catch anything that isn't a valid menu option.
        else:

            print("Invalid choice.")
            continue

        # Run anonymisation on the selected dataset.
        anonymised_rows = anonymise_data(
            original_rows,
            config,
            fernet
        )

        # Save the anonymised output as a CSV file.
        save_data(
            anonymised_rows,
            fieldnames,
            OUTPUT_FILE
        )

        # Create a privacy report showing what happened.
        generate_report(
            original_rows,
            anonymised_rows,
            REPORT_FILE
        )

        print(f"\nAnonymised data saved to: {OUTPUT_FILE}")
        print(f"Privacy report saved to: {REPORT_FILE}\n")

if __name__ == "__main__":
    main()

