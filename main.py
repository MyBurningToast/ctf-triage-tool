import subprocess
import argparse
from pathlib import Path
import shutil
import re
import base64

TESTING_FLAG = Path("tests") / "archive.zip" # temp for fast testing
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

ARCHIVE_MIME_TYPES = {
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
}


debug_log = None # set in main
def debug(label: str, value) -> None:
    line = f"[DEBUG] {label}: {value}"
    print(line)
    debug_log.write(line + "\n")

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

def process_file(path: Path, depth: int = 0) -> list[str]:
    flags = []

    #TODO: add a max depth and size. Just in case its a zip bomb or smthing

    working_copy = Path(SCRATCH_DIR) / path.name
    shutil.copy(path, working_copy)
    debug("Working copy", working_copy)

    result = subprocess.run(
        ["file", "--mime-type", "--brief", working_copy],
        capture_output=True, text=True, timeout=10
    )
    mime_type = result.stdout.strip()

    if mime_type in MIME_TO_EXTENSION:
        debug("MIME type detected", mime_type)
        true_extension = MIME_TO_EXTENSION[mime_type]
        
        current_extension = path.suffix
        if true_extension != current_extension: # we need to rename it
            working_copy = working_copy.rename(working_copy.with_suffix(true_extension))
            debug("Renamed working copy to", working_copy)
        else:
            debug("Extension correct", current_extension)

    else:
        debug("Unknown MIME type", mime_type)


    result = subprocess.run(
        ["strings", working_copy],
        capture_output=True, text=True, timeout=10
    )

    flags.extend(search_for_flag(result.stdout, FLAG_PREFIX))

    result = subprocess.run(
    ["exiftool", str(working_copy)],
    capture_output=True, text=True, timeout=10
    )
    #debug("Exiftool output", result.stdout)
    debug("Running exiftool", "")
    flags.extend(search_for_flag(result.stdout, FLAG_PREFIX))


    # only extract if file is actually an archive type
    # 7z will try "extract" the internal structure of non archive files
    if mime_type in ARCHIVE_MIME_TYPES:
        extract_dir = Path(SCRATCH_DIR) / f"extracted_{depth}" / working_copy.stem
        result = subprocess.run(
            ["7z", "x", str(working_copy), f"-o{extract_dir}", "-y"],
            capture_output=True, text=True, timeout=20
        )

        if result.returncode == 0 and extract_dir.exists():
            debug("Extracted archive", extract_dir)
            for extracted_file in extract_dir.rglob("*"): # recursively search the directory
                if extracted_file.is_file():
                    flags.extend(process_file(extracted_file, depth + 1))
        else:
            debug("Not an archive or extraction failed", working_copy)

    return flags

def main():
    global debug_log
    Path(SCRATCH_DIR).mkdir(exist_ok=True)

    with open("debug.log", "w") as debug_log:

        all_flags = []

        try:
            all_flags.extend(process_file(TESTING_FLAG))
            extract_dir = Path(SCRATCH_DIR) / "extracted"

        finally: # Clean up files after use
            scratch_path = Path(SCRATCH_DIR).resolve()
            debug("Deleting", scratch_path)
            shutil.rmtree(scratch_path, ignore_errors=True) # Im so scared of this lol

    print("--------------")
    if all_flags:
        print(f"Flags found: {all_flags}")
    else:
        print("Flag not found")



main()