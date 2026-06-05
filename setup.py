import sys
from setuptools import setup, find_packages


setup(
    name="reconnor",
    version="1.0.0",
    description="Educational Hacking & OSINT Suite - A collection of security analysis tools",
    url="https://github.com/enginestein/reconnor",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "colorama>=0.4.6",
        "Pillow>=9.0.0",
        "dnspython>=2.3.0",
        "cryptography>=3.4.0",
        "pysocks>=1.7.1",
    ],
    extras_require={
        "ext": [
            "sublist3r",
            "wafw00f",
            "dnsrecon",
            "linkfinder",
        ],
        "all": [
            "sublist3r",
            "wafw00f",
            "dnsrecon",
            "linkfinder",
        ],
        "dev": ["pytest", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "reconnor=main:main",
            "reconnor-setup=utils.install_deps:main",
        ],
    },
    python_requires=">=3.8",
)
