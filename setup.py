# setup.py

from setuptools import setup, find_packages

setup(
    name="BlackClown",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "torch",
        "transformers",
        "requests",
        "pygments"
    ],
    entry_points={
        "console_scripts": [
            "blackclown=src.blackclown:main",
        ],
    },
)
