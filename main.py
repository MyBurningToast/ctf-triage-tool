import subprocess
import argparse
from pathlib import Path
import shutil
import re
import base64

TESTING_FLAG = Path("tests") / "test_flag.txt" # temp for fast testing
FLAG_PREFIX = "flag"
SCRATCH_DIR = "scratch"

parser = argparse.ArgumentParser(description="CTF file triage tool")
#parser.add_argument("-f", "--file", required=True, help="path to target file")
#parser.add_argument("-F", "--format", required=True, help="flag format, if flag is 'xyz{abc123}' you can enter 'xyz'")
args = parser.parse_args()

#TODO: add more types
MIME_TO_EXTENSION = {
    "text/plain": ".txt",
    "image/png": ".png",
    "image/jpeg": ".jpg",
}

def search_for_flag(text: str, flag_prefix: str) -> list[str]:
    matches = []
    flag_regex = re.escape(flag_prefix) + r"\{.*?\}"

    # plain text search
    matches.extend(re.findall(flag_regex, text))

    # hex search
    hex_prefix = (flag_prefix + "{").encode("utf-8").hex()
    hex_matches = re.findall(hex_prefix + r"[0-9a-fA-F]*", text)
    #debug("Hex candidates found", hex_matches)

    for hex_match in hex_matches:
        decoded = bytes.fromhex(hex_match).decode("utf-8", errors="ignore")
        #debug("Decoded hex candidate", decoded)
        matches.extend(re.findall(flag_regex, decoded))

    # base64 search
    base64_candidates = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)
    #debug("Base64 candidates found", base64_candidates)

    for candidate in base64_candidates:
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            #debug("Decoded base64 candidate", decoded)
            matches.extend(re.findall(flag_regex, decoded))
        except Exception:
            continue # not valid base64, skip it

    return matches

flags_found = []
with open("debug.log", "w") as debug_log:
    def debug(label: str, value) -> None:
        line = f"[DEBUG] {label}: {value}"
        print(line)
        debug_log.write(line + "\n")

    #original = Path(args.file)
    original = TESTING_FLAG
    debug("Target file", original)
    working_copy = Path(SCRATCH_DIR) / original.name
    Path(SCRATCH_DIR).mkdir(exist_ok=True)
    shutil.copy(original, working_copy)
    debug("Working copy", working_copy)

    result = subprocess.run(
        ["file", "--mime-type", "--brief", working_copy],
        capture_output=True,
        text=True,
        timeout=10
    )

    mime_type = result.stdout.strip()

    if mime_type in MIME_TO_EXTENSION:
        debug("MIME type detected", mime_type)
        true_extension = MIME_TO_EXTENSION[mime_type]
        
        current_extension = original.suffix
        if true_extension != current_extension: # we need to rename it
            working_copy = working_copy.rename(working_copy.with_suffix(true_extension))
            debug("Renamed working copy to", working_copy)
        else:
            debug("Extension correct", current_extension)

    else:
        debug("Unknown MIME type", mime_type)


    result = subprocess.run(
        ["strings", working_copy],
        capture_output=True,
        text=True,
        timeout=10
    )

    flags_found.extend(search_for_flag(result.stdout, FLAG_PREFIX))

    # Clean up files after use
    def delete_scratch_dir():
        scratch_path = Path(SCRATCH_DIR).resolve()
        debug("Deleting", scratch_path)
        shutil.rmtree(scratch_path, ignore_errors=True) # Im so scared of this lol

    delete_scratch_dir()

print("--------------")
if (len(flags_found) >= 1):
    print(f"Flags found: {flags_found}")
else:
    print("Flag not found")