#!/usr/bin/env python3
"""
ML Attack Detection System for Red Team Exercises
A comprehensive machine learning framework for detecting and analyzing attack patterns.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ml-attack-detection",
    version="0.1.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Machine Learning Attack Detection System for Red Team Exercises",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/security-research/ml-attack-detection",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "gpu": [
            "torch[gpu]>=2.0.0",
            "tensorflow[gpu]>=2.13.0",
        ],
        "viz": [
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "plotly>=5.15.0",
            "graphviz>=0.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ml-attack-detection=ml_attack_detection.cli:main",
            "attack-trainer=ml_attack_detection.training.trainer:main",
            "threat-analyzer=ml_attack_detection.analysis.analyzer:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ml_attack_detection": [
            "models/*.pkl",
            "models/*.joblib",
            "models/*.onnx",
            "config/*.yaml",
            "data/*.json",
        ],
    },
)