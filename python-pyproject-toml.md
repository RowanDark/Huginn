[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "huginn-ai"
version = "0.1.0"
description = "AI and ML analysis module for Huginn OSINT platform"
authors = [
{name = "Your Name", email = "your.email@example.com"}
]
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
"fastapi>=0.104.0",
"uvicorn[standard]>=0.24.0",
"redis>=5.0.0",
"transformers>=4.35.0",
"torch>=2.1.0,<2.2.0",
"numpy>=1.24.0",
"pandas>=2.1.0",
"scikit-learn>=1.3.0",
"spacy>=3.7.0",
"nltk>=3.8.0",
"stix2>=3.0.0",
"requests>=2.31.0",
"pydantic>=2.5.0",
"python-multipart>=0.0.6",
"aioredis>=2.0.0",
"httpx>=0.25.0",
"loguru>=0.7.0",
"python-dotenv>=1.0.0",
"asyncio-mqtt>=0.13.0",
"sentence-transformers>=2.2.0",
"textblob>=0.17.0",
"yara-python>=4.3.0",
"python-magic>=0.4.0",
"pytz>=2023.3",
]

[project.optional-dependencies]
dev = [
"pytest>=7.4.0",
"pytest-asyncio>=0.21.0",
"black>=23.0.0",
"isort>=5.12.0",
"flake8>=6.0.0",
"mypy>=1.6.0",
"pre-commit>=3.5.0",
]

[project.urls]
"Homepage" = "https://github.com/yourusername/huginn"
"Bug Reports" = "https://github.com/yourusername/huginn/issues"
"Source" = "https://github.com/yourusername/huginn"

[tool.setuptools.packages.find]
where = ["src"]

[tool.black]
line-length = 88
target-version = ['py311']
include = '.pyi?$'

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_.py"
python_classes = "Test"
python_functions = "test_*"
asyncio_mode = "auto"
