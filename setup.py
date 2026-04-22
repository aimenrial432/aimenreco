import os
from setuptools import setup, find_packages
from typing import List

def parse_requirements(filename: str) -> List[str]:
    """
    Helper to parse requirements.txt and filter out comments/empty lines.
    """
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as f:
        return [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith(("#", "-"))
        ]

# Read long description from README
long_description: str = ""
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()

# Load all requirements
all_reqs = parse_requirements("requirements.txt")

# Split regular requirements from test dependencies
# (This assumes your requirements.txt has those # comments we saw)
install_requires = [r for r in all_reqs if not any(x in r for x in ["pytest", "responses"])]
test_requires = [r for r in all_reqs if any(x in r for x in ["pytest", "responses"])]

setup(
    name="aimenreco",
    version="3.3.0",
    author="Aimenrial",
    description="Advanced OSINT & Active Reconnaissance Framework",
    long_description=long_description,
    long_description_content_type="markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'aimenreco': ['resources/*'],
    },
    install_requires=install_requires,
    extras_require={
        "test": test_requires + ["mypy>=1.9.0"],
    },
    entry_points={
        "console_scripts": [
            "aimenreco=aimenreco.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
    python_requires='>=3.10',
)