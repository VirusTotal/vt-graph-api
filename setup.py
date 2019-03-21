import setuptools

setuptools.setup(
    name="vt_graph_api",
    version="0.0.1",
    author="VirusTotal",
    author_email="vt_graph_api@virustotal.com",
    description="VirusTotal Graph API",
    long_description_content_type="text/markdown",
    url="https://github.com/virustotal/vt_graph_api",
    packages=setuptools.find_packages(),
    install_requires=['requests'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
