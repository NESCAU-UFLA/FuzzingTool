import os
from setuptools import setup, find_packages

from src.fuzzingtool import __version__


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'requests>=2.25.1',
    'beautifulsoup4>=4.9.3',
    'dnspython>=2.1.0',
]

dev_requires = [
    'pytest'
]

setup(
    name="FuzzingTool",
    version=__version__,
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
            'FuzzingTool = fuzzingtool.fuzzingtool:main_cli'
        ]
    },
    install_requires=install_requires,
    extras_require={
        'dev': dev_requires
    },
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
