from google.cloud import storage
from google.api_core.exceptions import GoogleAPICallError
import csv
import os
from datetime import datetime

class BucketScanner:
    def __init__(self, project_id):
        self.project_id = project_id
        self.storage_client = storage.Client(project=project_id)

    def check_bucket_public_access(self, bucket):
        """CIS 5.1: Ensure Cloud Storage buckets are not publicly accessible"""
        policy = bucket.get_iam_policy(requested_policy_version=3)
        public_members = {"allUsers", "allAuthenticatedUsers"}
        
        for binding in policy.bindings:
            if public_members.intersection(binding["members"]):
                return False, f"Public access granted via {binding['role']}"
        return True, "No public access detected"

    def check_uniform_bucket_level_access(self, bucket):
        """CIS 5.2: Ensure uniform bucket-level access is enabled"""
        if bucket.iam_configuration.uniform_bucket_level_access_enabled:
            return True, "Uniform bucket-level access enabled"
        return False, "Uniform bucket-level access disabled"

    def scan_buckets(self):
        findings = []
        try:
            for bucket in self.storage_client.list_buckets():
                # CIS 5.1 Check
                compliant, msg = self.check_bucket_public_access(bucket)
                findings.append({
                    "control_id": "CIS 5.1",
                    "status": "PASS" if compliant else "FAIL",
                    "resource": f"gs://{bucket.name}",
                    "message": msg,
                    "severity": "High" if not compliant else "Low",
                    "recommendation": "Remove public access" if not compliant else "No action needed"
                })
                
                # CIS 5.2 Check
                compliant, msg = self.check_uniform_bucket_level_access(bucket)
                findings.append({
                    "control_id": "CIS 5.2",
                    "status": "PASS" if compliant else "FAIL",
                    "resource": f"gs://{bucket.name}",
                    "message": msg,
                    "severity": "Medium" if not compliant else "Low",
                    "recommendation": "Enable uniform bucket-level access" if not compliant else "No action needed"
                })
            
            # Write findings to CSV
            report_file = os.path.join("reports", "CIS_Benchmarks_Scan_Report.csv")
            with open(report_file, mode='w', newline='') as csvfile:
                fieldnames = ['control_id', 'status', 'resource', 'message', 'severity', 'recommendation']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write report title and date
                writer.writerow({'control_id': 'CIS Benchmarks Scan Report', 'status': '', 'resource': '', 'message': '', 'severity': '', 'recommendation': ''})
                writer.writerow({'control_id': f'Date: {datetime.now().strftime("%Y-%m-%d")}', 'status': '', 'resource': '', 'message': '', 'severity': '', 'recommendation': ''})
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding)

                # Summary row
                total_buckets = len(findings) // 2  # Assuming two checks per bucket
                failed_checks = sum(1 for finding in findings if finding['status'] == "FAIL")
                writer.writerow({'control_id': 'Summary', 'status': f'{failed_checks}/{total_buckets} Failed', 'resource': '', 'message': '', 'severity': '', 'recommendation': ''})

            print(f"Report generated: {report_file}")

        except GoogleAPICallError as e:
            print(f"Bucket scan error: {e}")
        return findings
