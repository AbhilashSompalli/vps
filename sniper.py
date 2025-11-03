import os
import subprocess
import traceback
import sys
import logging
import argparse
import time
import xml.etree.ElementTree as ET
from static_tools import sensitive_info_extractor, scan_android_manifest_root
from report_gen import ReportGen, util

"""
    Title:      sniper
    Desc:       Android security insights in full spectrum.
    Author:     Kushal
    Version:    1.0.0
    GitHub URL: https://github.com/kushal9652/sniper
"""

logging.basicConfig(level=logging.ERROR, format="%(message)s")


class util(util):
    """
    A static class for which contain some useful variables and methods
    """

    @staticmethod
    def mod_print(text_output, color):
        """
        Better mod print. It gives the line number, file name in which error occured.
        """
        stack = traceback.extract_stack()
        filename, line_no, func_name, text = stack[-2]
        formatted_message = f"{filename}:{line_no}: {text_output}"
        print(color + formatted_message + util.ENDC)

    @staticmethod
    def print_logo():
        """
        Logo for sniper
        """
        logo = f"""                 
{util.OKGREEN}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣶⣶⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣼⣷⡶⠶⠶⠶⠦⠤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⡆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⣠⣾⣿⣿⣶⣶⣶⣶⣶⣶⣿⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣿⣶⣧⣤⣤⣤⣤⣤⣤⣤⣶
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢿⣿⣿⣿⡿⠿⠛⠋⣩⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠓⠚⣿⣿⣿⠀⠀⢠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠀⠀⠀⠿⠛⠋⣀⣶⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⣤⣶⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣤⣀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⣿⣿⣲⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠹⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⢸⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⢀⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⢿⣿⣿⣿⣷⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀🪖🎖️💪                                              - Made By Kushal{util.ENDC}
        """
        print(logo)


def parse_args():
    """
    Parse command-line arguments.
    """
    util.print_logo()

    parser = argparse.ArgumentParser(
        description=(
            "{BOLD}{GREEN}sniper:{ENDC}"
            " Android Application security!. "
        ).format(
            BOLD=util.BOLD, GREEN=util.OKCYAN, ENDC=util.ENDC
        ),
        epilog=(
            "For more information, visit our GitHub repository"
            " - https://github.com/kushal9652/sniper-sih"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-apk",
        metavar="APK",
        type=str,
        required=True,
        help="Path to APK file to be analyzed.",
    )
    parser.add_argument(
        "-v",
        "-version",
        action="version",
        version="sniper v1.0",
        help="Display the version of sniper.",
    )
    parser.add_argument(
        "-source_code_path",
        metavar="APK",
        type=str,
        help="Enter valid path of extracted source for apk.",
    )
    parser.add_argument(
        "-report",
        choices=["json", "pdf", "html", "txt"],
        default="json",
        help="Format of the report to be generated. Default is JSON.",
    )
    parser.add_argument(
        "-o",
        metavar="output path or file",
        type=str,
        help="Output report path (filename or directory)"
    )
    parser.add_argument(
        "--ignore_virtualenv",
        action="store_true",
        help="Ignore virtual environment check.",
    )
    parser.add_argument("-l", metavar="log level", help="Set the logging level")
    return parser.parse_args()


class AutoSniperScanner(ReportGen):

    def __init__(self):
        pass

    def create_extraction_dir(self, apk_file, extracted_path=None):
        """
        Creating a folder to extract apk source code
        """
        extracted_source_code_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file
        )

        resource_code_path = os.path.join(extracted_source_code_path, "resources")
        source_code_path = os.path.join(extracted_source_code_path, "sources")

        if (
            os.path.exists(extracted_source_code_path)
            and os.path.isdir(extracted_source_code_path)
            and os.path.exists(resource_code_path)
            and os.path.isdir(resource_code_path)
            and os.path.exists(source_code_path)
            and os.path.isdir(source_code_path)
        ):
            util.mod_log(
                "[+] Source code for apk - {} Already extracted. Skipping this step.".format(
                    apk_file
                ),
                util.OKCYAN,
            )
            return {"result": 0, "path": extracted_source_code_path}
        else:
            os.makedirs(extracted_source_code_path, exist_ok=True)
            util.mod_log(
                "[+] Creating new directory for extracting apk : "
                + extracted_source_code_path,
                util.OKCYAN,
            )
            return {"result": 1, "path": extracted_source_code_path}

    def decompile_apk(self, apk_file, extraction_dir):
        """
        Extracting source code with JADX
        """
        util.mod_log("[+] Extracting the source code to: " + extraction_dir, util.OKCYAN)

        def is_running_in_docker():
            return os.path.exists('/.dockerenv') or (
                os.path.isfile('/proc/1/cgroup') and 'docker' in open('/proc/1/cgroup').read()
            )

        is_windows = os.name == "nt"
        in_docker = is_running_in_docker()

        jadx_executable = "jadx.bat" if is_windows else "jadx"

        if in_docker and False:
            jadx_path = "/app/static_tools/jadx/bin/jadx"
        else:
            jadx_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "static_tools",
                "jadx",
                "bin",
                jadx_executable,
            )

        try:
            result = subprocess.run(
                [jadx_path, apk_file, "-d", extraction_dir],
                capture_output=True,
                text=True,
                check=True
            )
            util.mod_log("[+] jadx ran successfully.", util.OKGREEN)
            util.mod_log(result.stdout, util.OKBLUE)
        except subprocess.CalledProcessError as e:
            util.mod_log("[-] jadx failed to run. Unable to Extract {} source code".format(apk_name), util.FAIL)
            util.mod_log("Return code: " + str(e.returncode), util.WARNING)
            util.mod_log("Stdout:\n" + e.stdout, util.WARNING)
            util.mod_log("Stderr:\n" + e.stderr, util.WARNING)
        except FileNotFoundError:
            util.mod_log(f"[-] jadx not found at: {jadx_path}", util.FAIL)

    def get_absolute_path(self, path):
        """
        Returns the absolute path
        """
        return os.path.abspath(path)

    def check_apk_existence(self, apk_filename):
        """
        Check if the apk file exists or not.
        """
        return os.path.isfile(apk_filename)


if __name__ == "__main__":
    try:
        args = parse_args()

        ignore_virtualenv = args.ignore_virtualenv
        # Check if virtual environment is activated 
        if not os.path.exists("/.dockerenv") and not ignore_virtualenv:
            try:
                os.environ["VIRTUAL_ENV"]
            except KeyError:
                util.mod_log(
                    "[-] ERROR: Not inside virtualenv. Do source venv/bin/activate",
                    util.FAIL,
                )
                exit(1)

            if not args.apk:
                util.mod_log(
                    "[-] ERROR: Please provide the apk file using the -apk flag.", util.FAIL
                )
                exit(1)

        apk = args.apk

        def get_apk_name_and_path(apk):
            """
            Added function to better handle apk names and apk paths
            """
            global apk_name, apk_path

            if os.sep in apk:
                apk_name = os.path.basename(apk)  # Extracts the filename from the path
                apk_path = apk
                return "file path"
            else:
                apk_name = apk
                apk_path = apk
                return "It's just the filename"

        # Calling function to handle apk names and path.
        get_apk_name_and_path(apk)

        # Results dict store all the response in json.
        analysis_results = {
            "apk_name": apk_name,
            "package_name": "",
            "permission": "",
            "dangerous_permission": "",
            "manifest_root_analysis": "",
            "hardcoded_secrets": "",
            "insecure_requests": "",
        }

        scanner = AutoSniperScanner()
        apk_abs_path = scanner.get_absolute_path(apk_path)
        if not scanner.check_apk_existence(apk_abs_path):
            util.mod_log(f"[-] ERROR: {apk_abs_path} not found.", util.FAIL)
            exit(1)
        else:
            util.mod_log(f"[+] {apk_abs_path} found!", util.OKGREEN)
        time.sleep(1)

        # Extracting source code
        extraction_dir = scanner.create_extraction_dir(
            apk_name,
            extracted_path=args.source_code_path if args.source_code_path else None,
        )
        if extraction_dir["result"] == 1:
            scanner.decompile_apk(apk_abs_path, extraction_dir["path"])

        # Extracting abs path of extracted source code dir
        extracted_source_abs_path = scanner.get_absolute_path(extraction_dir["path"])

        # Extraction useful infomration from android menifest file
        # scanner.extract_manifest_root_info(apk_name)
        extracted_source_code_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name
        )
        manifest_analysis_results = (
            scan_android_manifest_root.ScanAndroidManifestRoot().extract_manifest_info(
                extracted_source_code_path
            )
        )
        analysis_results["package_name"] = manifest_analysis_results["package_name"]
        analysis_results["permission"] = manifest_analysis_results["permissions"]
        analysis_results["dangerous_permission"] = manifest_analysis_results["dangerous_permission"]
        analysis_results["manifest_root_analysis"] = {
            "activities": {
                "all": manifest_analysis_results["activities"],
                "exported": manifest_analysis_results["exported_activity"],
            },
            "services": {
                "all": manifest_analysis_results["services"],
                "exported": manifest_analysis_results["exported_service"],
            },
            "receivers": {
                "all": manifest_analysis_results["receivers"],
                "exported": manifest_analysis_results["exported_receiver"],
            },
            "providers": {
                "all": manifest_analysis_results["providers"],
                "exported": manifest_analysis_results["exported_provider"],
            },
        }

        # Extracting hardcoded secrets
        report_generator = sensitive_info_extractor.SensitiveInfoExtractor()
        util.mod_log("[+] Reading all file paths ", util.OKCYAN)
        file_paths_for_secrets = report_generator.get_all_file_paths(extracted_source_abs_path)
        relative_to = extracted_source_abs_path
        util.mod_log("[+] Extracting all hardcoded secrets ", util.OKCYAN)
        hardcoded_secrets_analysis_results = report_generator.extract_all_sensitive_info(
            file_paths_for_secrets, relative_to
        )
        if isinstance(hardcoded_secrets_analysis_results, list):
            analysis_results["hardcoded_secrets"] = hardcoded_secrets_analysis_results
        else:
            analysis_results["hardcoded_secrets"] = []

        # extracting insecure connections
        util.mod_log("[+] Extracting all insecure connections ", util.OKCYAN)
        file_paths_for_insecure_requests = report_generator.get_all_file_paths(extracted_source_abs_path)
        result = report_generator.extract_insecure_request_protocol(file_paths_for_insecure_requests)
        print(result)
        if isinstance(result, list):
            analysis_results["insecure_requests"] = result
        else:
            analysis_results["insecure_requests"] = []

        ############## REPORT GENERATION ############

        if args.report:

            # Extracting all the required paths
            extracted_source_code_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name
            )
            resource_code_path = os.path.join(extracted_source_code_path, "resources")
            source_code_path = os.path.join(extracted_source_code_path, "sources")
            script_directory = os.path.dirname(os.path.abspath(__file__))
            report_template_path = os.path.join(script_directory, "report_template.html")

            # Reading the android manifest_root file.
            manifest_root_path = os.path.join(resource_code_path, "AndroidManifest.xml")
            manifest_root_tree = ET.parse(manifest_root_path)
            manifest_root = manifest_root_tree.getroot()
            # Update the attributes by stripping out the namespace
            for elem in manifest_root.iter():
                elem.attrib = {
                    k.replace(
                        "{http://schemas.android.com/apk/res/android}", "android:"
                    ): v
                    for k, v in elem.attrib.items()
                }
            output_path = args.o

            # Creating report_generatorect for report generation module.
            report_generator = ReportGen(apk_name, manifest_root, resource_code_path, source_code_path, report_template_path, output_path)

            if args.report == "html":
                report_generator.generate_html_pdf_report(report_type="html")
            elif args.report == "pdf":
                report_generator.generate_html_pdf_report(report_type="pdf")
            elif args.report == "json":
                report_generator.create_json_report(analysis_results)
            elif args.report == "txt":
                report_generator.generate_txt_report(analysis_results)
            else:
                util.mod_print("[-] Invalid Report type argument provided", util.FAIL)

    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        line_number = exc_traceback.tb_lineno
        util.mod_print(f"[-] {str(e)} at line {line_number}", util.FAIL)
        exit(1)
