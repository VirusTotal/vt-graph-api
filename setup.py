"""Setup for vt_graph_api module."""


import re
import sys
import setuptools


with open("./vt_graph_api/version.py") as f:
  version = (
      re.search(r"__version__ = \'([0-9]{1,}.[0-9]{1,}.[0-9]{1,})\'",
                f.read()).groups()[0])

# check python version >2.7.x and >=3.2.x
installable = True
if sys.version_info.major == 3:
  if sys.version_info.minor < 2:
    installable = False
else:
  if sys.version_info.minor < 7:
    installable = False
if not installable:
  sys.exit("Sorry, this python version is not supported")

with open("README.md", "r") as fh:
  long_description = fh.read()

install_requires = [
    "requests",
    "six",
    "futures"
]

setuptools.setup(
    name="vt_graph_api",
    version=version,
    author="VirusTotal",
    author_email="vt_graph_api@virustotal.com",
    description="The official Python client library for VirusTotal Graph API",
    license="Apache 2",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/virustotal/vt-graph-api",
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
