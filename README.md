# PyPI Package Scraper

**PyPI Package Scraper** is a Python-based tool designed to fetch, analyze, and report on the structure and security of Python packages from [PyPI](https://pypi.org/). This tool automates the inspection of packages for potential malicious behavior and dependency analysis.

## Features

- Automatically fetches the latest version and download link of a package using the PyPI API.
- Creates a separate directory for each analyzed package.
- Parses common metadata files such as `setup.py`, `requirements.txt`, and `METADATA` to extract dependencies.
- Integrates with the [VirusTotal API](https://www.virustotal.com/) to scan packages for malicious or suspicious indicators.  
  _Note: scanning may take some time depending on package size and VirusTotal response time._
- Uses regular expressions to detect risky behavior, including:
  - **Dynamic code execution** (`eval`, `exec`)
  - **Shell command execution** (`subprocess`, `os.system`)
  - **Network activity** (`requests`, `socket`)
  - **File operations** (`open`, `os.remove`)
  - And more.
- Generates a full analysis report saved in the corresponding package folder.

## Usage
### Scan a single PyPI package:
```
python scraper.py -p <package_name>
```

### Scan a list of PyPI packages:
```
python scraper.py -l <file.txt>
```

### Scan a single PyPI package:
```
python scraper.py -f <package_file_name>
```

# Notes!
Make sure to have an VirusTotal API key, and insert it inside the code.
If not, comment out the VirusTotal function, to pass the check, otherwise, it will loop forever.


# PoC

![image](https://github.com/user-attachments/assets/55df9513-055e-4f29-bfae-2936973340d5)
