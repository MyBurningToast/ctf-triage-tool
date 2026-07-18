import subprocess
import argparse
from pathlib import Path
import shutil
import re
import base64
import itertools

SCRATCH_DIR = "scratch"
MAX_DEPTH = 5

parser = argparse.ArgumentParser(description="CTF file triage tool")
subparsers = parser.add_subparsers(dest="command", required=True)

file_parser = subparsers.add_parser("file", help="triage a single file")
file_parser.add_argument("-f", "--file", required=True, help="path to target file")
file_parser.add_argument("-F", "--format", required=True, help="flag format, if flag is 'xyz{abc123}' you can enter 'xyz'")

batch_parser = subparsers.add_parser("batch", help="triage every file in a folder")
batch_parser.add_argument("-d", "--dir", required=True, help="folder of files to triage")
batch_parser.add_argument("-F", "--format", required=True, help="flag format, if flag is 'xyz{abc123}' you can enter 'xyz'")

args = parser.parse_args()

TARGET_FILE = Path(args.file) if args.command == "file" else None
FLAG_PREFIX = args.format

MIME_TO_EXTENSION = {
    "text/plain": ".txt",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "application/pdf": ".pdf",
    "audio/x-wav": ".wav",
    "audio/basic": ".au",
}

ARCHIVE_MIME_TYPES = {
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
}

copy_counter = itertools.count() # keeps working copies unique across recursion


def search_for_flag(text: str, flag_prefix: str) -> list[str]:
    matches = []
    flag_regex = re.escape(flag_prefix) + r"\{.*?\}"

    # plain text search
    matches.extend(re.findall(flag_regex, text))

    # hex search
    hex_prefix = (flag_prefix + "{").encode("utf-8").hex()
    hex_matches = re.findall(hex_prefix + r"[0-9a-fA-F]*", text)

    for hex_match in hex_matches:
        decoded = bytes.fromhex(hex_match).decode("utf-8", errors="ignore")
        matches.extend(re.findall(flag_regex, decoded))

    # base64 search
    base64_candidates = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)

    for candidate in base64_candidates:
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            matches.extend(re.findall(flag_regex, decoded))
        except Exception:
            continue # not valid base64, skip it

    return matches

def process_file(path: Path, depth: int = 0) -> list[str]:
    flags = []

    print(f"[{depth}] scanning {path.name}")

    if depth > MAX_DEPTH:
        print(f"[{depth}] max depth hit, skipping {path.name}")
        return flags

    working_copy = Path(SCRATCH_DIR) / f"{next(copy_counter)}_{path.name}"
    shutil.copy(path, working_copy)

    result = subprocess.run(
        ["file", "--mime-type", "--brief", working_copy],
        capture_output=True, text=True, timeout=10
    )
    mime_type = result.stdout.strip()

    if mime_type in MIME_TO_EXTENSION:
        true_extension = MIME_TO_EXTENSION[mime_type]
        
        current_extension = path.suffix
        if true_extension != current_extension: # we need to rename it
            working_copy = working_copy.rename(working_copy.with_suffix(true_extension))


    result = subprocess.run(
        ["strings", working_copy],
        capture_output=True, text=True, timeout=10
    )

    flags.extend(search_for_flag(result.stdout, FLAG_PREFIX))

    result = subprocess.run(
    ["exiftool", str(working_copy)],
    capture_output=True, text=True, timeout=10
    )
    flags.extend(search_for_flag(result.stdout, FLAG_PREFIX))

    if mime_type == "image/png":
        result = subprocess.run(
            ["zsteg", str(working_copy)],
            capture_output=True, text=True, timeout=10
        )
        flags.extend(search_for_flag(result.stdout, FLAG_PREFIX))

    if mime_type in ("image/jpeg", "image/bmp", "audio/x-wav", "audio/basic"):
        # steghide writes extracted data to a file, not stdout
        steghide_out = working_copy.with_suffix(working_copy.suffix + ".steghide_out")
        result = subprocess.run( # try with an empty password
            ["steghide", "extract", "-sf", str(working_copy), "-p", "", "-xf", str(steghide_out), "-f"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and steghide_out.exists():
            flags.extend(search_for_flag(steghide_out.read_text(errors="ignore"), FLAG_PREFIX))

    if mime_type in ("image/png", "image/jpeg"):
        result = subprocess.run(
            ["zbarimg", str(working_copy)],
            capture_output=True, text=True, timeout=10
        )
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
            for extracted_file in extract_dir.rglob("*"): # recursively search the directory
                if extracted_file.is_file():
                    flags.extend(process_file(extracted_file, depth + 1))

    flags = list(set(flags)) # remove duplicates
    return flags

def run_one(path: Path) -> list[str]:
    Path(SCRATCH_DIR).mkdir(exist_ok=True)

    try:
        flags = process_file(path)
    finally: # Clean up files after use
        scratch_path = Path(SCRATCH_DIR).resolve()
        shutil.rmtree(scratch_path, ignore_errors=True) # Im so scared of this lol

    return flags

def run_challenge(item: Path) -> list[str]:
    if item.is_file():
        return run_one(item)

    # item is a folder, treat every file inside it as part of this one challenge
    flags = []
    for sub_item in sorted(item.rglob("*")):
        if sub_item.is_file():
            flags.extend(run_one(sub_item))

    return list(set(flags))

def main():
    if args.command == "file":
        flags = run_one(TARGET_FILE)
        print("--------------")
        if flags:
            print(f"Flags found: {flags}")
        else:
            print("Flag not found")

    elif args.command == "batch":
        batch_dir = Path(args.dir)

        with open("results.txt", "w") as results_file:
            for item in sorted(batch_dir.iterdir()):
                print(f"=== {item.name} ===")
                flags = run_challenge(item)

                if flags:
                    results_file.write(f"{item.name}: {flags}\n")
                else:
                    results_file.write(f"{item.name}: Flag not found\n")
                results_file.flush()



main()