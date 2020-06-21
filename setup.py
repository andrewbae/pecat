#!/usr/bin/env python3

import setuptools

setuptools.setup(
    name="pecat",
    version="0.0.1",
    license="MIT",
    author="Andrew Bae",
    author_email="dev4ndr3w@gmail.com",
    description="An open-source multi-platform Windows Portable Executable(PE) analyzing module",
    url="https://github.com/dev4ndr3w/pecat",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        ],
    python_requires='>=3.6'
)
