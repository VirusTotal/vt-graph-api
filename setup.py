"""Setup fro vt_graph_api module."""


import sys
import setuptools
from vt_graph_api import version


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
    version=version.__version__,
    author="VirusTotal",
    author_email="vt_graph_api@virustotal.com",
    description="VirusTotal Graph API",
    license="Apache 2",
    long_description_content_type="text/markdown",
    url="https://github.com/virustotal/vt_graph_api",
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
