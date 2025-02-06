try:
    from google.cloud import storage
    from google.cloud import iam_v1
    from google.cloud import resourcemanager_v3
    print("Imports successful!")
except ImportError as e:
    print(f"Import error: {e}")
