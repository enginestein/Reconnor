from setuptools import setup, find_packages

setup(
    name="reconner",
    version="1.0.0",
    description="Educational Hacking & OSINT Suite - A collection of security analysis tools",
    url="https://github.com/enginestein/reconner",
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "colorama>=0.4.6",
        "Pillow>=9.0.0",
        "dnspython>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "reconner=main:main",
        ],
    },
    python_requires=">=3.8",
)
