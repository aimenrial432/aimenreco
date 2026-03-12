from setuptools import setup, find_packages

setup(
    name="aimenreco",
    version="3.0",
    packages=find_packages(), # Esto encontrará la carpeta 'dirforcer'
    include_package_data=True,
    package_data={
        'aimenreco': ['resources/*'], # Importante para los JSON y TXT
    },
    install_requires=[
        "requests",
        "pyfiglet",
    ],
    entry_points={
        "console_scripts": [
            # Comando = paquete.archivo:función
            "aimenreco=aimenreco.cli:main",
        ],
    },
)