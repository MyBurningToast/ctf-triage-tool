# CTF Triage Tool

Automated first-pass triage for CTF forensics / steganography challenges.

Point it at a file or a folder of challenge files and it runs a standard set of forensics tools against each one (`strings`, `exiftool`, `zsteg`, `steghide`, `zbarimg`, archive extraction with `7z`), searches every tool's output for a flag in your target format. It's meant to save the first five minutes of every challenge and run the obvious tools.

## What it does

For each file, `ctf-triage-tool`:

1. Copies the file into a scratch directory
2. Identifies the true file type via `file --mime-type` and fixes the extension if it's wrong
3. Runs `strings` and `exiftool` and scans the output for your flag format
4. Runs format specific tools:
    - PNGs - `zsteg`
    - JPEG / BMP / WAV / AU  - `steghide extract` (empty password)
    - PNG / JPEG - `zbarimg` (barcode/QR extraction)
5. If the file is an archive (zip, gzip, tar, 7z, rar), extracts it with `7z` and recurses into every extracted file (up to a max depth)
6. Will then report the flags found

## Requirements

- Python 3.9+
- The following tools available on `PATH`:
    - [`file`](https://man7.org/linux/man-pages/man1/file.1.html)
    - [`exiftool`](https://exiftool.org/)
    - [`zsteg`](https://github.com/zed-0xff/zsteg)
    - [`steghide`](http://steghide.sourceforge.net/)
    - [`zbarimg`](https://github.com/mchehab/zbar) (part of `zbar-tools`)
    - `7z` (`p7zip-full`)

On Debian/Ubuntu (or WSL2):

```bash
sudo apt install file exiftool steghide zbar-tools p7zip-full ruby-full
gem install zsteg
```

## Usage

### Single file

```bash
python main.py file -f challenge.png -F "flag"
```

Triages `challenge.png`, searching for flags like `flag{...}`

### Batch mode

```bash
python main.py batch -d ./challenges -F "flag"
```

Treats every top-level item in `./challenges` as its own challenge. Writes a running summary to `results.txt` and prints it at the end.

### Flags

| Flag             | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `-f`, `--file`   | Path to a single target file (`file` command only)     |
| `-d`, `--dir`    | Path to a folder of challenges (`batch` command only)  |
| `-F`, `--format` | Flag prefix to search for, e.g. `flag` for `flag{...}` |

## Flag detection

Flags are searched for in three encodings within every tool's output:

- **Plain text** - direct regex match on `prefix{...}`
- **Hex encoded** -  matches the hex bytes of `prefix{` and decodes forward
- **Base64** - finds base64 looking substrings, decodes them, and checks the result

## Project structure

```
ctf-triage-tool/
├── main.py       # CLI entry point and triage logic
├── tests/        # sample challenge files for testing
├── scratch/      # created and cleaned up automatically at runtime
└── results.txt   # store any flags found for that run
```

## AI Notice
The flags in `tests/` were **generated with Claude AI**.
## Notes
- This is a **first-pass** tool, not a replacement for manual analysis. It catches the easy stuff so you can spend your time on the challenges that actually need it. Happy hacking :)
