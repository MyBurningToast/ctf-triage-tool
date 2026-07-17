import subprocess
import argparse
from pathlib import Path
import shutil

TESTING_FLAG = Path("tests") / "test_flag2.png" # temp for fast testing

parser = argparse.ArgumentParser(description="CTF file triage tool")
parser.add_argument("-f", "--file", required=True, help="path to target file")
#parser.add_argument("-F", "--format", required=True, help="flag format, if flag is 'xyz{abc123}' you can enter 'xyz'")
args = parser.parse_args()

#TODO: add more types
MIME_TO_EXTENSION = {
    "text/plain": ".txt",
    "image/png": ".png",
    "image/jpeg": ".jpg",
}

def true_extension(mime_type: str) -> str:
    return MIME_TO_EXTENSION.get(mime_type, "")

def with_corrected_extension(path: Path, correct_ext: str) -> Path:
    return path.with_suffix(correct_ext)


#original = Path(args.file)
original = TESTING_FLAG
working_copy = Path("scratch") / original.name
Path("scratch").mkdir(exist_ok=True)
shutil.copy(original, working_copy)

result = subprocess.run(
    ["file", "--mime-type", "--brief", working_copy],
    capture_output=True,
    text=True,
    timeout=10
)

#corrected_path = working_copy.rename(with_corrected_extension(working_copy, ".jpg"))

print(result.stdout)


# Clean up files after use
def delete_scratch_dir():
    scratch_path = Path("scratch").resolve()
    print(f"Deleting: {scratch_path}")
    shutil.rmtree(scratch_path, ignore_errors=True) # Im so scared of this lol

delete_scratch_dir()