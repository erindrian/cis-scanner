from setuptools import setup, find_packages

setup(
    name="gcp-cis-scanner",
    version="0.1.0",
    description="A tool to audit GCP environments against CIS Benchmark v3.0 controls for Cloud Storage and IAM.",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/gcp-cis-scanner",  # Replace with your repository URL
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "google-cloud-storage>=2.0.0",
        "google-cloud-iam>=2.0.0",
        "google-cloud-resource-manager>=1.0.0",
        "python-dotenv>=0.19.0"
    ],
    entry_points={
        "console_scripts": [
            "gcp-cis-scan=main:main",  # Entry point for the command line interface
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)