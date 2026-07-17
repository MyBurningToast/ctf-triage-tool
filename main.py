import subprocess
import argparse
from pathlib import Path
import shutil

TESTING_FLAG = Path("tests") / "test_flag.txt" # temp for fast testing
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




    # Clean up files after use
    def delete_scratch_dir():
        scratch_path = Path(SCRATCH_DIR).resolve()
        debug("Deleting", scratch_path)
        shutil.rmtree(scratch_path, ignore_errors=True) # Im so scared of this lol

    delete_scratch_dir()
    debug("Flag found", False)