from setuptools import setup, find_packages

setup(
    name="vulnforge",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests>=2.31.0",
        "httpx>=0.27.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "click>=8.0.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "vulnforge=vulnforge.cli:main",
        ],
    },
)
