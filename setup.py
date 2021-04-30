import os
import sys
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

install_requires = ['requests']

if sys.platform.startswith("win"):
    install_requires.append("colorama>=0.4.0")

setup(
    name="FuzzingTool",
    version="3.9.2",
    author="Vitor Oriel C N Borges",
    author_email="vitorwixmix@gmail.com",
    description=("Software for fuzzing, used on web application pentestings."),
    long_description=read('./README.md'),
    long_description_content_type='text/markdown',
    license="MIT",
    keywords="pentesting-tools python3 fuzzing web-security",
    url="https://github.com/NESCAU-UFLA/FuzzingTool/",
    packages=find_packages(where='src'),
    package_dir={'fuzzingtool': 'src/fuzzingtool'},
    entry_points={
        'console_scripts': [
            'FuzzingTool = fuzzingtool.FuzzingTool:main'
        ]
    },
    install_requires=install_requires,
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3"
    ],
)
