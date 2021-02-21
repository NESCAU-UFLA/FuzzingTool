import os
import sys
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

install_requires = ['requests']

if sys.platform.startswith("win"):
    install_requires.append("colorama>=0.4.0")

setup(
    name = "FuzzingTool",
    version = "3.6.0",
    author = "Vitor Oriel C N Borges",
    author_email = "vitorwixmix@gmail.com",
    description = ("Software for fuzzing, used on web application pentestings."),
    long_description=read('./README.md'),
    license = "MIT",
    keywords = "pentesting-tools python3 fuzzing web-security",
    url = "https://github.com/NESCAU-UFLA/FuzzingTool/",
    packages=find_packages(where='./src', exclude=['input', 'reports', 'logs']),
    install_requires=install_requires,
    classifiers=[
        "Development Status :: 4 - Neta",
        "Natural Language :: English",
        "License :: MIT License",
        "Programming Language :: Python :: 3"
    ],
)