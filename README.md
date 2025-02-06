# GCP CIS Scanner

This project is a scanner for GCP CIS compliance. It audits GCP environments against CIS Benchmark v3.0 controls for Cloud Storage and IAM.

## Installation

To install the GCP CIS Scanner, clone the repository and install the required dependencies:

```
git clone https://github.com/yourusername/gcp-cis-scanner.git
cd gcp-cis-scanner
pip install -r requirements.txt
```

## Usage

To run the overall scanner, use the following command:

```
gcp-cis-scan
```

You can specify additional options as needed.

### Bucket Scanning

To run the bucket scanning functionality, use the following command:

```
python3 src/main.py --project YOUR_PROJECT_ID
```

Replace `YOUR_PROJECT_ID` with your actual GCP project ID.

The bucket scanning functionality checks GCP Cloud Storage buckets against CIS Benchmark controls. It verifies:

- That buckets are not publicly accessible.
- That uniform bucket-level access is enabled.

A report is generated in CSV format, which includes the following columns:
- Control ID
- Status
- Resource
- Message
- Severity
- Recommendation

The report also includes the date of the scan and a summary of the findings.

## Dependencies

The following libraries are required to run the GCP CIS Scanner:

- google-cloud-storage
- google-cloud-iam
- google-cloud-resource-manager
- python-dotenv

Make sure to install these dependencies using the `requirements.txt` file.
