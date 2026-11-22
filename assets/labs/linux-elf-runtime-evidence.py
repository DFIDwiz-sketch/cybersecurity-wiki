"""Build and observe an offline Linux ELF fixture in a temporary directory."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


LIBRARY = "int wiki_fixture_value(void) { return 7; }\n"
HOST = r"""
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static int fixture_mapped(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[8192];
    int found = 0;
    if (maps == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, "/libwiki_fixture.so\n") != NULL) {
            found = 1;
            break;
        }
    }

    if (ferror(maps)) {
        found = -1;
    }
    fclose(maps);
    return found;
}

int main(void)
{
    int before = fixture_mapped();
    if (before < 0) {
        fputs("Could not read procfs before loading\n", stderr);
        return 1;
    }

    void *handle = dlopen("./libwiki_fixture.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "Could not load the lab library: %s\n", dlerror());
        return 1;
    }

    int after = fixture_mapped();
    dlclose(handle);
    if (after < 0) {
        fputs("Could not read procfs after loading\n", stderr);
        return 1;
    }

    printf("%d %d\n", before, after);
    return 0;
}
"""


def run(command, directory):
    return subprocess.run(
        command,
        cwd=directory,
        env={**os.environ, "LC_ALL": "C"},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout


def check(condition, label):
    if not condition:
        raise SystemExit(f"FAIL: {label}")
    print(f"PASS: {label}")


def main():
    if sys.platform != "linux":
        raise SystemExit("This lab requires Linux and a readable /proc/self/maps.")
    for tool in ("cc", "readelf"):
        if shutil.which(tool) is None:
            raise SystemExit(f"Required tool not found: {tool}")

    try:
        with tempfile.TemporaryDirectory(prefix="wiki-elf-") as directory:
            path = Path(directory)
            (path / "library.c").write_text(LIBRARY, encoding="utf-8")
            (path / "host.c").write_text(HOST, encoding="utf-8")
            run(["cc", "-fPIC", "-shared", "library.c", "-o", "libwiki_fixture.so"], path)
            run(["cc", "host.c", "-o", "wiki-host", "-ldl"], path)
            dynamic = run(["readelf", "-d", "wiki-host"], path)
            check(
                "(NEEDED)" in dynamic and "libwiki_fixture.so" not in dynamic,
                "ELF declares startup dependencies, but not the lab plugin",
            )
            before, after = run(["./wiki-host"], path).strip().split()
            check(before == "0", "plugin is absent from the process maps before loading")
            check(after == "1", "plugin is mapped after the explicit runtime load")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Lab command failed: {error.stderr.strip()}") from error
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise SystemExit(f"Could not complete the lab: {error}") from error


if __name__ == "__main__":
    main()
