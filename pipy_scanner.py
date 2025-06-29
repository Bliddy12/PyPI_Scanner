import argparse
import sys
import requests
import os
import zipfile
import tarfile
import ast
import time
import re
import tempfile

#Change This:
API_KEY = 'X'

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = '\033[93m'
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"

class PyPIScraper:

    #Constructor for the class
    def __init__(self, package):
        self.package_name = package #Package name
        self.version = None #Version
        self.name = None #Downloaded file name
        self.extract_path = f"packages/{self.package_name}" #Package folder location
        self.dependencies = [] #Dependencies
        self.malicious_dependencies = 0
        self.suspicious_dependencies = 0
        self.undetected_dependencies = 0
        self.functions_categories = {} #Functions catagories(true or false)

    #Initiating run procedure
    def run(self):
        package_json = self.fetching_version()
        self.fetching_download(package_json)
        self.fetching_dependencies()

        #Activating malicious activity search
        self.virus_total(self.name)

        self.functions()
        self.report()

    #Attempting to find the current version of the package
    def fetching_version(self):
        print(f"{YELLOW}[+] Attempting to find and download package{RESET}")

        #Using PyPI API to scrap the version
        try:
            PYPI_API = f"https://pypi.org/pypi/{self.package_name}/json"
            response = requests.get(PYPI_API)

            #Error handler for common status code
            if response.status_code == 404:
                print(f"{RED}[-] Package not found on PyPI{RESET}")
                raise
            #Jsoning the data to extract the version
            package_json = response.json()
            version = package_json["info"]["version"]
            print(f"{CYAN}[+] Found Latest version: {version}{RESET}")
            self.version = version
            return package_json

        #Error handlers
        except requests.exceptions.RequestException as e:
            raise Exception(f"{RED}[-] Network Error: {e}{RESET}")
        except Exception as e:
            raise Exception(f"{RED}[-] Unexpected Error: {e}{RESET}")

    #Attempting to download the selected package
    def fetching_download(self,package_json):
        #Checking if download URL exist
        version = package_json["info"]["version"]
        files = package_json["releases"].get(version)
        if not files:
            print(f"{RED}[-] No download URL found...{RESET}")
            raise Exception(f"{RED}[-] Package not found on PyPI{RESET}")
        url = files[0]["url"]
        #Creating dedicated sub-folder to the downloaded package
        os.makedirs(self.extract_path, exist_ok=True)

        #Downloading the package to the dedicated sub-folder of 'packages' folder
        try:
            response = requests.get(url)
            filename = files[0]["filename"]
            self.name = filename
            filepath = os.path.join(self.extract_path, filename)
            with open(filepath, "wb") as f:
                f.write(response.content)
                if filename in os.listdir(self.extract_path):
                    print(f"{GREEN}[+] Download Completed!{RESET}")

        #Error handlers
        except requests.exceptions.RequestException as e:
            print(f"{RED}[-] Network Error: {e}{RESET}")
            raise Exception(f"{RED}[-] Package not found on PyPI{RESET}")
        except Exception as e:
            print(f"{RED}[-] Unexpected error: {e}{RESET}")
            raise Exception(f"{RED}[-] Package not found on PyPI{RESET}")

        #Checking which file extenstion downloaded
        try:
            if filename.endswith(".whl"):
                with zipfile.ZipFile(filepath, 'r') as whl:
                    whl.extractall(self.extract_path)
            elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
                with tarfile.open(filepath, 'r:gz') as tar:
                    tar.extractall(self.extract_path)

        #Error handler
        except Exception as e:
            print(f"{RED}[-] Unexpected error during extraction: {e}{RESET}")
            raise Exception(f"{RED}[-] Package not found on PyPI{RESET}")

    #Attempting to find the dependencies of the downloaded package
    def fetching_dependencies(self):
        found_setup_py = False
        found_requirements_txt = False
        found_metadata_txt = False

        target_files = ['setup.py', 'requirements.txt', 'METADATA']

        #all_files is an array of all files in the sub-folder
        all_files = []
        for root, dirs, files in os.walk(self.extract_path):
            for file in files:
                full_path = os.path.join(root, file)
                all_files.append(full_path)

        dependencies = []

        #Trying to find the target files recursivly inside the package sub-folder
        #Activating for each file its own function to handle dependencies scarp
        for path in all_files:
            filename = os.path.basename(path)
            if filename in target_files:
                if filename == 'requirements.txt':
                    found_requirements_txt = True
                    dependencies.extend(self.scrap_requirements_txt(path))
                    #print(f"{GREEN}[+] Found: {filename} at {path}{RESET}")
                elif filename == 'setup.py':
                    found_setup_py = True
                    #print(f"{GREEN}[+] Found: {filename} at {path}{RESET}")
                    dependencies.extend(self.scrap_setup_py(path))
                elif filename == 'METADATA':
                    found_metadata_txt = True
                    #print(f"{GREEN}[+] Found: {filename} at {path}{RESET}")
                    dependencies.extend(self.scrap_metadata(path))

        #Notification for missing files(not critical)
        if not found_setup_py:
            print(f"{YELLOW}[~] setup.py not found{RESET}")
        if not found_requirements_txt:
            print(f"{YELLOW}[~] requirements.txt not found{RESET}")
        if not found_metadata_txt:
            print(f"{YELLOW}[~] METADATA not found{RESET}")

        #Checking if dependencies found
        if dependencies:
            print(f"{GREEN}[+] Printing dependencies:{RESET}\n")
            for dep in dependencies:
                print(f'{CYAN} - {dep}{RESET}')
            self.dependencies = dependencies
        else:
            print(f"{GREEN}[+] No dependencies found{RESET}")

    #Getting requirements.txt dependencies
    def scrap_requirements_txt(self, path):
        deps = []
        with open(path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line.startswith('#'):
                deps.append(line)
        return deps

    #Getting setup.py dependencies
    def scrap_setup_py(self, path):
        deps = []

        #Using ast module to map the structor of the setup.py program
        with open(path, 'r') as f:
            tree = ast.parse(f.read(), filename=path)

        #Grabbing the 'install_requires' values from the ast tree
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'setup':
                for kw in node.keywords:
                    if kw.arg == 'install_requires':
                        for item in kw.value.elts:
                            if isinstance(item, ast.Constant):
                                deps.append(item.value)
        return deps

    #Getting METADATA dependencies
    def scrap_metadata(self, path):
        deps = []

        with open(path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if line.startswith("Requires-Dist:"):
                dep = line[len("Requires-Dist:"):].split(";")[0].strip()
                deps.append(dep)

        return deps


    def virus_total(self,name):
        #Using virus total API to fetch malicious activity
        print('\n')
        print(f'{GREEN}[+] Attempting to find malicious activity with VirusTotal...{RESET}')
        url = "https://www.virustotal.com/api/v3/files"
        package_path = self.extract_path+'/'+name
        files = { "file": (name, open(package_path, "rb"), "application/octet-stream") }
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        response = requests.post(url, files=files, headers=headers)
        
        response_json = response.json()

        analysis_id = response_json["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        print(f"{GREEN}[+] File uploaded. Analysis ID: {analysis_id}{RESET}")
        print(f"{GREEN}[~] Waiting for scan results...{RESET}")

        #Scanning file and waiting for the final json response
        while True:
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_data = analysis_response.json()

            #Uncomment to check if VirusTotal API quota exeeded....
            #print("Debugging:", analysis_data)
            
            status = analysis_data["data"]["attributes"]["status"]
            if status == "completed":
                # Printing results summary
                stats = analysis_data["data"]["attributes"]["stats"]
                print(f"{GREEN}[+] Scan completed!{RESET}")

                #Printing handlers
                if stats["malicious"] > 0:
                    print(f"{RED}[-] Malicious: {stats['malicious']}{RESET}")
                else:
                    print(f"{GREEN}[+] Malicious: {stats['malicious']}{RESET}")

                if stats["suspicious"] > 0:
                    print(f"{RED}[-] Suspicious: {stats['suspicious']}{RESET}")
                else:
                    print(f"{GREEN}[+] Suspicious: {stats['suspicious']}{RESET}")
                print(f"{GREEN}[+] Undetected: {stats['undetected']}{RESET}")

                if stats["malicious"] > 0 or stats["suspicious"] > 0:
                    print(f"{RED}[-] PACKAGE MAY BE MALICIOUS!!!{RESET}")
                else:
                    print(f"{CYAN}[+] The package appears to be clean.{RESET}")
                break

            else:
                print(f"{YELLOW}[+] Scanning still taking place, please wait...{RESET}")
                time.sleep(20)

        self.malicious_dependencies = stats['malicious']
        self.suspicious_dependencies = stats['suspicious']
        self.undetected_dependencies = stats['undetected']



    def functions(self):

        functions_report = []

        #Checking catagories to make the behavior 
        category_flags = {
            "exec/eval": False,
            "subprocess/shell": False,
            "networking": False,
            "file access": False,
            "dynamic import": False,
            "encryption": False,
            "obfuscation": False,
            "env/system info": False,
            "input capture": False,
            "scanning/exploiting": False,
            "web automation": False,
            "persistence": False
        }

        #Commands to check on the .py files
        patterns = {
            "exec/eval": r"\b(exec|eval|compile|execfile)\b",
            "subprocess/shell": r"\b(subprocess|os\.system|popen|shlex|pty|commands)\b",
            "networking": r"\b(requests|httpx|urllib|socket|ftplib|httplib|telnetlib)\b",
            "file access": r"\b(open|write|read|os\.remove|os\.unlink|os\.rmdir|shutil)\b",
            "dynamic import": r"\b(__import__|importlib|imp)\b",
            "encryption": r"\b(hashlib|cryptography|Crypto|base64|binascii)\b",
            "obfuscation": r"\b(base64|binascii|marshal|zlib|codecs|rot13)\b",
            "env/system info": r"\b(os\.environ|platform|sys\.platform|os\.uname|getpass|getenv)\b",
            "input capture": r"\b(pynput|keyboard|mouse|pyautogui|win32api)\b",
            "scanning/exploiting": r"\b(nmap|scapy|socket\.socket|paramiko|telnetlib|pexpect)\b",
            "web automation": r"\b(selenium|mechanize|requests_html|BeautifulSoup|lxml)\b",
            "persistence": r"\b(winreg|os\.startfile|crontab|schtasks|launchctl)\b"
        }

        for root, dirs, files in os.walk(self.extract_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, 'r') as f:
                            lines = f.readlines()
                            for line in lines:
                                for category in patterns:
                                    pattern = patterns[category]

                                    #Using regular expression to find the commands
                                    if re.search(pattern, line):
                                        functions_report.append("[" + category + "] " + file + ":" + line.strip())
                                        category_flags[category] = True
                    except:
                        pass

        print(f"{GREEN}[+] Functions summary collected with {len(functions_report)} findings.{RESET}")
        self.functions_categories = category_flags

    def report(self):

        print(f'{GREEN}[+] Writing report file{RESET}')

        #Adding report.txt to sub-folder
        report_path = os.path.join(self.extract_path, "report.txt")
        with open(report_path,"w") as f:
            if self.malicious_dependencies > 0 or self.suspicious_dependencies > 0:
                f.write(f"Package: {self.package_name} (MAY BE MALICIOUS!)\n")
            else:
                f.write(f"Package: {self.package_name}\n")

            f.write("\n")
            f.write(f"Version: {self.version}\n")
            f.write("\n")
            f.write(f"Downloaded file: {self.name}\n")
            f.write("\n")
            f.write(f"Found dependencies from setup.py + METADATA + requirements.txt:\n")
            f.write("\n")
            for dep in self.dependencies:
                f.write(f"{dep}\n")
            f.write("\n")
            f.write("Scanning Results from VirusTotal API:\n")
            f.write("\n")
            f.write(f"Malicious dependencies detected: {self.malicious_dependencies}\n")
            f.write(f"Suspicious dependencies detected: {self.suspicious_dependencies}\n")
            f.write(f"Undetected dependencies: {self.undetected_dependencies}\n")
            f.write("\nFunctions Summary:\n")

            explanations = {
                "exec/eval": "Program uses `exec`/`eval`/`compile` — allows running dynamic code, which can be risky.",
                "subprocess/shell": "Program uses subprocess or shell calls (e.g., subprocess, os.system) — may execute system commands.",
                "networking": "Program uses networking libraries (requests, socket, ftplib, etc.) — may connect to the internet or other machines.",
                "file access": "Program reads/writes or modifies files and directories — can access or change local data.",
                "dynamic import": "Program imports code dynamically (`__import__`, importlib) — can load code at runtime.",
                "encryption": "Program uses encryption libraries (hashlib, Crypto) — may encrypt or decrypt data.",
                "obfuscation": "Program uses encoding or compression (base64, marshal, zlib) — may be to hide code or data.",
                "env/system info": "Program accesses environment variables or system info — may collect sensitive system details.",
                "input capture": "Program uses libraries to capture keyboard/mouse input — can be used for keylogging.",
                "scanning/exploiting": "Program uses scanning or exploitation tools (nmap, scapy, paramiko) — may perform network scanning or attacks.",
                "web automation": "Program automates web browsing or scraping (selenium, BeautifulSoup) — interacts with websites.",
                "persistence": "Program attempts persistence techniques (winreg, crontab) — may try to maintain access.",
            }

            for functions_type in self.functions_categories:
                if self.functions_categories[functions_type]:
                    f.write(f"{explanations[functions_type]}\n")


#Analyze a single local package file
def analyze_archive_functions(file_path):

    if not (tarfile.is_tarfile(file_path) or zipfile.is_zipfile(file_path)):
        print(f"{RED}[-] Not a supported archive {file_path}{RESET}")
        return

    #Determine which package file extenstion is and extracting to sub-folder
    base_name = os.path.basename(file_path)
    base_name_no_ext = os.path.splitext(base_name)[0].replace(".tar", "") 
    extract_path = os.path.join("packages", f"{base_name_no_ext}")
    os.makedirs(extract_path, exist_ok=True)

    #Extract the archive
    try:
        if tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r:*') as tar:
                tar.extractall(path=extract_path)
            print(f"{GREEN}[+] Extracted .tar to: {extract_path}{RESET}")
        elif zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            print(f"{GREEN}[+] Extracted .whl to: {extract_path}{RESET}")

    except Exception as e:
        print(f"{RED}[-] Failed to extract: {e}{RESET}")
        return

    functions_report = []

    #Checking catagories to make the behavior
    category_flags = {
        "exec/eval": False,
        "subprocess/shell": False,
        "networking": False,
        "file access": False,
        "dynamic import": False,
        "encryption": False,
        "obfuscation": False,
        "env/system info": False,
        "input capture": False,
        "scanning/exploiting": False,
        "web automation": False,
        "persistence": False
    }

    #Commands to check on the .py files
    patterns = {
        "exec/eval": r"\b(exec|eval|compile|execfile)\b",
        "subprocess/shell": r"\b(subprocess|os\.system|popen|shlex|pty|commands)\b",
        "networking": r"\b(requests|httpx|urllib|socket|ftplib|httplib|telnetlib)\b",
        "file access": r"\b(open|write|read|os\.remove|os\.unlink|os\.rmdir|shutil)\b",
        "dynamic import": r"\b(__import__|importlib|imp)\b",
        "encryption": r"\b(hashlib|cryptography|Crypto|base64|binascii)\b",
        "obfuscation": r"\b(base64|binascii|marshal|zlib|codecs|rot13)\b",
        "env/system info": r"\b(os\.environ|platform|sys\.platform|os\.uname|getpass|getenv)\b",
        "input capture": r"\b(pynput|keyboard|mouse|pyautogui|win32api)\b",
        "scanning/exploiting": r"\b(nmap|scapy|socket\.socket|paramiko|telnetlib|pexpect)\b",
        "web automation": r"\b(selenium|mechanize|requests_html|BeautifulSoup|lxml)\b",
        "persistence": r"\b(winreg|os\.startfile|crontab|schtasks|launchctl)\b"
    }


    for root, dirs, files in os.walk(extract_path):
                for file in files:
                    if file.endswith(".py"):
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, 'r') as f:
                                lines = f.readlines()
                                for line in lines:
                                    for category in patterns:
                                        pattern = patterns[category]

                                        #Using regular expression to find the commands
                                        if re.search(pattern, line):
                                            functions_report.append("[" + category + "] " + file + ":" + line.strip())
                                            category_flags[category] = True
                        except:
                            pass

    print(f"{GREEN}[+] Functions summary collected with {len(functions_report)} findings.{RESET}")

    for category, flagged in category_flags.items():
        if flagged:
            print(f"{YELLOW}[~] {category}{RESET}")

    report_path = os.path.join(extract_path, "report.txt")
    print(f'{GREEN}[+] Writing report to: {report_path}{RESET}')

    explanations = {
        "exec/eval": "Program uses `exec`/`eval`/`compile` - allows running dynamic code, which can be risky.",
        "subprocess/shell": "Program uses subprocess or shell calls (e.g., subprocess, os.system) - may execute system commands.",
        "networking": "Program uses networking libraries (requests, socket, ftplib, etc.) - may connect to the internet or other machines.",
        "file access": "Program reads/writes or modifies files and directories - can access or change local data.",
        "dynamic import": "Program imports code dynamically (`__import__`, importlib) - can load code at runtime.",
        "encryption": "Program uses encryption libraries (hashlib, Crypto) - may encrypt or decrypt data.",
        "obfuscation": "Program uses encoding or compression (base64, marshal, zlib) - may be to hide code or data.",
        "env/system info": "Program accesses environment variables or system info - may collect sensitive system details.",
        "input capture": "Program uses libraries to capture keyboard/mouse input - can be used for keylogging.",
        "scanning/exploiting": "Program uses scanning or exploitation tools (nmap, scapy, paramiko) - may perform network scanning or attacks.",
        "web automation": "Program automates web browsing or scraping (selenium, BeautifulSoup) - interacts with websites.",
        "persistence": "Program attempts persistence techniques (winreg, crontab) - may try to maintain access.",
    }

    
    with open(report_path, "w") as f:
        f.write(f"Local File Analysis Report for: {file_path}\n")
        f.write("Detected Function Categories:\n")
        for category in category_flags:
            if category_flags[category]:
                f.write(f"- {category}: {explanations[category]}\n")

    is_malicious = any(category_flags.values())
    if is_malicious:
        print(f'{RED}[-] FILE MAY BE MALICIOUS!!!{RESET}')

def main():

    #Argument Parser
    parser = argparse.ArgumentParser(description="PyPI Package Scraper Helper")
    parser.add_argument('-p', '--package', type=str, help="Name of the package to scrap")
    parser.add_argument('-l', '--list', type=str, help="List of packages(txt file)")
    parser.add_argument('-f', '--file', type=str, help="Local file to scan")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    #Handling single package
    if args.package:
        try:
            scraper = PyPIScraper(args.package)
            scraper.run()
        except Exception:
            #Avoid printing errors twice since the PyPIScraper class already handle that
            pass

    #Handling list of packages
    if args.list:
        packages = []
        with open(args.list,'r') as l:
            for line in l:
                line = line.strip()
                if line:
                    packages.append(line)
            for package in packages:
                print(f"{BOLD}\n[+] Processing: {package}{RESET}")
                try:
                    scraper = PyPIScraper(package)
                    scraper.run()
                except Exception:
                    #Avoid printing errors twice since the PyPIScraper class already handle that
                    pass

    if args.file:
        try:
            analyze_archive_functions(args.file)
        except Exception:
            #Avoid printing errors twice since the PyPIScraper class already handle that
            pass

    print(f'{GREEN}[+] Scrap Completed :) !{RESET}')

if __name__ == "__main__":
    main()