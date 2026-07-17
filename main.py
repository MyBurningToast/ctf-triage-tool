import subprocess
import argparse

parser = argparse.ArgumentParser(description="CTF file triage tool")
parser.add_argument("-f", "--file", required=True, help="path to target file")
#parser.add_argument("-F", "--format", required=True, help="flag format, if flag is 'xyz{abc123}' you can enter 'xyz'")
#parser.add_argument("-o", "--output", required=False, help="optional path to write report to")
#parser.add_argument("-v", "--verbose", action="store_true", help="show full raw tool output")
args = parser.parse_args()

target = args.file

result = subprocess.run(
    ["cat", target],
    capture_output=True,
    text=True,
    timeout=10
)

print(result.stdout)
#print(result.stderr)
#print(result.returncode)