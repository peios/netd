"""Check netd's staged network payload without launching applications or applying seeds."""

import gzip
import json
import os
import re
import subprocess
from pathlib import Path

BINARIES = ("netd", "net")
LIBDIR = "usr/lib/x86_64-linux-peios"


def require(condition: bool, message: str) -> None:
    """Keep package gates effective when Python assertions are disabled."""
    if not condition:
        raise ValueError(message)


def readelf(path: Path, option: str) -> str:
    """Read one ELF view, tolerating binary CRC bytes in the debug-link section."""
    return subprocess.check_output(
        ["readelf", option, str(path)],
        text=True,
        errors="replace",
        env=os.environ | {"LC_ALL": "C"},
    )


def build_id(notes: str, path: Path) -> str:
    """Extract the single GNU build identity required by split debugging."""
    matches = re.findall(r"Build ID: ([0-9a-f]+)", notes)
    require(len(matches) == 1 and len(matches[0]) >= 3, f"{path}: missing or ambiguous build ID")
    return matches[0]


def validate_elf(stage: Path, binary: str, *, native: bool) -> None:
    """Require linked hardening and the matching shared-family split debug payload."""
    library = binary == "libnetd"
    elf = stage / (
        LIBDIR + "/libnetd.so.1"
        if library
        else ("usr/sbin/netd" if binary == "netd" else "usr/bin/net")
    )
    require(elf.is_file() and os.access(elf, os.X_OK), f"{elf}: missing executable")
    header, program, dynamic = (readelf(elf, option) for option in ("-h", "-lW", "-dW"))
    notes, sections = readelf(elf, "-n"), readelf(elf, "-SW")
    require(bool(re.search(r"Type:\s+DYN\b", header)), f"{elf}: not position independent")
    require("GNU_RELRO" in program and "BIND_NOW" in dynamic, f"{elf}: missing full RELRO")
    stack = [line for line in program.splitlines() if "GNU_STACK" in line]
    require(len(stack) == 1 and bool(re.search(r"\sRW\s", stack[0])), f"{elf}: executable stack")
    if not library:
        require(bool(re.search(r"FLAGS_1.*\bPIE\b", dynamic)), f"{elf}: missing PIE flag")
    if binary in {"netd", "net", "libnetd"}:
        require("Shared library: [libpeios.so.0]" in dynamic, f"{elf}: missing libpeios linkage")
    if library:
        require("Library soname: [libnetd.so.1]" in dynamic, f"{elf}: incorrect client SONAME")
    if binary == "net":
        require(
            "Shared library: [libnetd.so.1]" in dynamic, f"{elf}: client is not dynamically linked"
        )
    require(not re.search(r"\((RPATH|RUNPATH|TEXTREL)\)", dynamic), f"{elf}: unsafe dynamic tag")
    require(".debug_info" not in sections, f"{elf}: unsplit debug information")
    if native:
        require("IBT" in notes and "SHSTK" in notes, f"{elf}: missing native CET properties")
        require(bool(re.search(r"\(RELR\)", dynamic)), f"{elf}: missing native packed relocations")
    identity = build_id(notes, elf)
    component = binary
    debug = stage / f"debug/{component}/usr/lib/debug/.build-id/{identity[:2]}/{identity[2:]}.debug"
    require(debug.is_file() and debug.stat().st_size > 0, f"{elf}: missing split debug file")
    require(".debug_info" in readelf(debug, "-SW"), f"{debug}: missing debug information")
    require(build_id(readelf(debug, "-n"), debug) == identity, f"{debug}: build ID mismatch")
    require(debug.name in readelf(elf, "--string-dump=.gnu_debuglink"), f"{elf}: wrong debug link")
    forbidden = {str(Path.cwd().resolve()), str(Path.cwd().resolve()).split("/execroot/")[0]}
    for path in (elf, debug):
        contents = path.read_bytes()
        for prefix in forbidden:
            require(len(prefix) <= 1 or prefix.encode() not in contents, f"{path}: leaked {prefix}")


def validate_data(stage: Path) -> None:
    """Check inert registry seeds, references, public headers, and the protected state root."""
    for name in ("netd.8", "net.1", "libnetd.3"):
        manual = stage / f"usr/share/man/man{name[-1]}/{name}.gz"
        with gzip.open(manual, "rt", encoding="utf-8") as stream:
            require(
                bool(re.search(r"^\.TH ", stream.read(), re.MULTILINE)),
                f"missing heading: {manual}",
            )
    directory = stage / "usr/share/regim"
    expected = {path.name for path in Path("registry.d").glob("*.reg")}
    require({path.name for path in directory.iterdir()} == expected, "incomplete registry seeds")
    for path in directory.iterdir():
        require(
            json.loads(path.read_text())
            == json.loads((Path("registry.d") / path.name).read_text()),
            f"changed seed: {path}",
        )
    state = stage / "var/state/netd"
    require(state.is_dir() and not any(state.iterdir()), "missing or populated state directory")
    for name in ("netd.regman", "netd.evman"):
        kind = name.rsplit(".", 1)[1]
        require(
            (stage / f"usr/share/{kind}/{name}").read_bytes() == (Path("docs") / name).read_bytes(),
            f"changed reference: {name}",
        )
    require(
        (stage / LIBDIR / "libnetd.so").readlink() == Path("libnetd.so.1"), "wrong linker symlink"
    )
    for name in ("netd.h", "netd-types.h"):
        require((stage / "usr/include/peios" / name).is_file(), f"missing public header: {name}")


def validate(stage: Path, *, native: bool, sdk: Path) -> None:
    """Check staged binaries without running the privileged daemon or applying registry seeds."""
    require(sdk.is_dir(), "missing declared SDK")
    for binary in (*BINARIES, "libnetd"):
        validate_elf(stage, binary, native=native)
    validate_data(stage)
    environment = os.environ | {
        "LD_LIBRARY_PATH": str((stage / LIBDIR).resolve()) + ":" + str((sdk / "lib").resolve())
    }
    client = stage / "usr/bin/net"
    result = subprocess.run(
        [client, "version"], capture_output=True, text=True, env=environment, check=True
    )
    require(result.stdout.strip() == "net 0.1.8", "wrong client version")
    result = subprocess.run([client], capture_output=True, text=True, env=environment, check=False)
    require(result.returncode == 2 and "usage: net status" in result.stderr, "wrong client usage")
