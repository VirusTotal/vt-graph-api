from distutils.util import convert_path
import sys
import setuptools

vt_graph_api_info = {}
with open(convert_path('vt_graph_api/version.py')) as ver_file:
  exec(ver_file.read(), vt_graph_api_info)

with open("README.md", "r") as fh:
  long_description = fh.read()

install_requires = [
    'requests'
]

setuptools.setup(
    name="vt_graph_api",
    version=vt_graph_api_info['__version__'],
    author="VirusTotal",
    author_email="vt_graph_api@virustotal.com",
    description="VirusTotal Graph API",
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
