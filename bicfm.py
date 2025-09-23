#!/usr/bin/env python3
"""
bicfm - Binary Integrity & Control Flow Monitor (Part 1)
Supports: init, scan, scan-dir, show
"""

import argparse
import json
import os
import hashlib
import sys
from colorama import init as color_init, Fore, Style
from elftools.elf.elffile import ELFFile

color_init(autoreset=True)

DB_FILE = "bicfm_db.json"
BUF_SIZE = 65536


def sha256sum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(BUF_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def extract_elf_metadata(path):
    meta = {"sections": {}, "compiler": None}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                try:
                    size = int(section.header['sh_size'])
                except Exception:
                    try:
                        size = int(section['sh_size'])
                    except Exception:
                        size = 0
                meta["sections"][section.name] = size

            # Extract compiler info from .comment or note-like sections
            csec = elf.get_section_by_name(".comment")
            if csec:
                try:
                    data = csec.data().decode("utf-8", errors="ignore").strip()
                    if data:
                        meta["compiler"] = data
                except Exception:
                    pass
            if not meta["compiler"]:
                # try any note-like section
                for section in elf.iter_sections():
                    if "note" in section.name.lower():
                        try:
                            data = section.data().decode("utf-8", errors="ignore").strip()
                            if data:
                                meta["compiler"] = data
                                break
                        except Exception:
                            continue
    except Exception:
        # not an ELF or parsing problem
        pass
    return meta

def load_db(path=DB_FILE):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL, "Failed to read DB file:", path)
        return {}

def save_db(db, path=DB_FILE):
    with open(path, "w") as f:
        json.dump(db, f, indent=2)
    return True

def compare_sections(baseline_sections, current_sections):
    # returns list of human-readable diffs
    diffs = []
    base_keys = set(baseline_sections.keys())
    curr_keys = set(current_sections.keys())

    added = curr_keys - base_keys
    removed = base_keys - curr_keys
    common = base_keys & curr_keys

    for s in sorted(added):
        diffs.append(f"section added: {s} ({current_sections[s]} bytes)")
    for s in sorted(removed):
        diffs.append(f"section removed: {s} ({baseline_sections[s]} bytes)")
    for s in sorted(common):
        if baseline_sections[s] != current_sections[s]:
            diffs.append(
                f"section size changed: {s} {baseline_sections[s]} -> {current_sections[s]} bytes"
            )
    return diffs

# -----------------------
# Command implementations
# -----------------------
def cmd_init(args):
    target_dir = args.dir
    if not os.path.isdir(target_dir):
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"{target_dir} is not a directory")
        return 1

    db = {}
    count = 0
    for root, _, files in os.walk(target_dir):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                if not is_elf(path):
                    continue
                real = os.path.realpath(path)
                sha = sha256sum(path)
                size = os.path.getsize(path)
                meta = extract_elf_metadata(path)
                entry = {
                    "path": path,         # original path (may be symlink)
                    "realpath": real,     # resolved path
                    "sha256": sha,
                    "size": size,
                    "sections": meta.get("sections", {}),
                    "compiler": meta.get("compiler"),
                }
                db[real] = entry
                count += 1
                print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"Added {path}")
            except (PermissionError, OSError):
                # skip unreadable files
                continue
    save_db(db)
    print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"Baseline created for {count} binaries in {target_dir}")
    print(Fore.GREEN + "[OK]" + Style.RESET_ALL, f"Baseline saved to {DB_FILE}")
    return 0

def check_against_db(path, db):
    real = os.path.realpath(path)
    if real not in db:
        return "MISSING", "Not found in baseline"
    entry = db[real]
    try:
        current_sha = sha256sum(path)
    except Exception as e:
        return "MISSING", f"Unreadable: {e}"
    if current_sha != entry.get("sha256"):
        # Hash mismatch -> violation
        # also compute section diffs if possible
        current_meta = extract_elf_metadata(path)
        diffs = compare_sections(entry.get("sections", {}), current_meta.get("sections", {}))
        msg = "Hash mismatch"
        if diffs:
            msg += "; " + "; ".join(diffs[:3])  # short summary
        else:
            msg += "; metadata differs"
        return "VIOLATION", msg
    else:
        # Hash same - check metadata anomalies (size/sections/compiler)
        current_meta = extract_elf_metadata(path)
        anomalies = []
        if int(os.path.getsize(path)) != int(entry.get("size", 0)):
            anomalies.append(f"size {entry.get('size')} -> {os.path.getsize(path)}")
        sec_diffs = compare_sections(entry.get("sections", {}), current_meta.get("sections", {}))
        if sec_diffs:
            anomalies.extend(sec_diffs)
        baseline_comp = entry.get("compiler")
        current_comp = current_meta.get("compiler")
        if (baseline_comp or "") != (current_comp or ""):
            anomalies.append("compiler metadata changed")
        if anomalies:
            return "SUSPICIOUS", "; ".join(anomalies[:4])
        return "OK", "Integrity verified"

def cmd_scan(args):
    file_path = args.file
    if not os.path.exists(file_path):
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"{file_path} does not exist")
        return 1
    if not is_elf(file_path):
        print(Fore.YELLOW + "[SUSPICIOUS]" + Style.RESET_ALL, f"{file_path} is not an ELF binary")
        return 0
    db = load_db()
    if not db:
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, "Baseline database not found or empty. Run 'bicfm init <dir>' first.")
        return 1

    status, msg = check_against_db(file_path, db)
    if status == "OK":
        print(Fore.GREEN + "[OK]" + Style.RESET_ALL, f"{file_path} - {msg}")
    elif status == "SUSPICIOUS":
        print(Fore.YELLOW + "[SUSPICIOUS]" + Style.RESET_ALL, f"{file_path} - {msg}")
    elif status == "VIOLATION":
        print(Fore.RED + "[VIOLATION]" + Style.RESET_ALL, f"{file_path} - {msg}")
    elif status == "MISSING":
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"{file_path} - {msg}")
    return 0

def cmd_scan_dir(args):
    target_dir = args.dir
    if not os.path.isdir(target_dir):
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL, f"{target_dir} is not a directory")
        return 1
    db = load_db()
    if not db:
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, "Baseline database not found or empty. Run 'bicfm init <dir>' first.")
        return 1

    counters = {"OK":0, "SUSPICIOUS":0, "VIOLATION":0, "MISSING":0}
    total = 0
    for root, _, files in os.walk(target_dir):
        for fname in files:
            path = os.path.join(root, fname)
            if not is_elf(path):
                continue
            total += 1
            status, msg = check_against_db(path, db)
            if status == "OK":
                counters["OK"] += 1
                print(Fore.GREEN + "[OK]" + Style.RESET_ALL, path)
            elif status == "SUSPICIOUS":
                counters["SUSPICIOUS"] += 1
                print(Fore.YELLOW + "[SUSPICIOUS]" + Style.RESET_ALL, path, "-", msg)
            elif status == "VIOLATION":
                counters["VIOLATION"] += 1
                print(Fore.RED + "[VIOLATION]" + Style.RESET_ALL, path, "-", msg)
            elif status == "MISSING":
                counters["MISSING"] += 1
                print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, path, "-", msg)

    print()
    print(Fore.GREEN + "[OK]" + Style.RESET_ALL, f" {counters['OK']} binaries verified")
    if counters["SUSPICIOUS"]:
        print(Fore.YELLOW + "[SUSPICIOUS]" + Style.RESET_ALL, f" {counters['SUSPICIOUS']} binaries suspicious")
    if counters["VIOLATION"]:
        print(Fore.RED + "[VIOLATION]" + Style.RESET_ALL, f" {counters['VIOLATION']} binaries failed")
    if counters["MISSING"]:
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f" {counters['MISSING']} binaries not in baseline")
    print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"Scanned {total} ELF binaries in {target_dir}")
    return 0

def cmd_show(args):
    file_path = args.file
    db = load_db()
    if not db:
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, "Baseline database not found or empty. Run 'bicfm init <dir>' first.")
        return 1
    real = os.path.realpath(file_path)
    if real not in db:
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"{file_path} is not in baseline")
        return 0
    entry = db[real]
    print(Fore.BLUE + "[INFO]" + Style.RESET_ALL, f"Baseline entry for {file_path}")
    print("  Path:    ", entry.get("path"))
    print("  Real:    ", entry.get("realpath"))
    print("  SHA256:  ", entry.get("sha256"))
    print("  Size:    ", entry.get("size"))
    print("  Compiler:", entry.get("compiler"))
    print("  Sections:")
    for s, sz in sorted(entry.get("sections", {}).items()):
        print(f"    {s:20} {sz} bytes")
    return 0

# -----------------------
# CLI wiring
# -----------------------
def main():
    parser = argparse.ArgumentParser(prog="bicfm", description="Binary Integrity & Control Flow Monitor")
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="Initialize baseline for directory")
    p_init.add_argument("dir", help="Directory to scan")
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="Scan a single binary against baseline")
    p_scan.add_argument("file", help="File to scan")
    p_scan.set_defaults(func=cmd_scan)

    p_scandir = sub.add_parser("scan-dir", help="Scan a directory of binaries against baseline")
    p_scandir.add_argument("dir", help="Directory to scan")
    p_scandir.set_defaults(func=cmd_scan_dir)

    p_show = sub.add_parser("show", help="Show baseline info for a binary")
    p_show.add_argument("file", help="File to show")
    p_show.set_defaults(func=cmd_show)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
    rc = args.func(args)
    sys.exit(rc if isinstance(rc, int) else 0)

if __name__ == "__main__":
    main()

