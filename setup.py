from setuptools import setup, find_packages

setup(
    name="aimenreco",
    version="3.1.0",  # Updated to reflect our memory optimization sprint
    author="Aimenrial",
    description="Advanced OSINT & Active Reconnaissance Framework",
    long_description=open("README.md").read(),
    long_description_content_type="markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'aimenreco': ['resources/*'],
    },
    install_requires=[
        "requests>=2.31.0",
        "pyfiglet>=1.0.2",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "aimenreco=aimenreco.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    python_requires='>=3.10',
)