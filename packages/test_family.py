"""Check the assembled package boundaries and retained installation policy."""

import json
import tomllib
import unittest
from pathlib import Path


class FamilyTests(unittest.TestCase):
    """Validate canonical manifests rather than only their recipe inputs."""

    def setUp(self) -> None:
        self.root = Path("packages.store")
        self.index = json.loads((self.root / "index.json").read_text())
        self.packages = {
            item["name"].removeprefix("dev.peios."): item for item in self.index["packages"]
        }
        self.files = {
            name: tomllib.loads((self.root / item["manifest"]).read_text())["files"]
            for name, item in self.packages.items()
        }

    def test_complete_unsigned_family(self) -> None:
        self.assertEqual(
            set(self.packages),
            {
                "netd",
                "net",
                "libnetd",
                "libnetd-devel",
                "netd-debuginfo",
                "net-debuginfo",
                "libnetd-debuginfo",
                "netd-debugsource",
                "netd-source",
            },
        )
        self.assertEqual(self.index["package_count"], 9)
        self.assertFalse(self.index["release_ready"])
        for item in self.packages.values():
            self.assertEqual(item["version"], "0.1.8-1")
            self.assertFalse(item["release_ready"])
            if "build" in item:
                self.assertFalse(item["build"]["signed"])
                self.assertIn(
                    item["build"]["userspace_abi"], {"debian-development", "peios-native"}
                )

    def test_runtime_ownership_and_state_policy(self) -> None:
        for name, binary in {
            "netd": "usr/sbin/netd",
            "net": "usr/bin/net",
            "libnetd": "usr/lib/x86_64-linux-peios/libnetd.so.1",
        }.items():
            for other, files in self.files.items():
                self.assertEqual(binary in files, other == name)
            self.assertTrue(self.files[name][binary]["exec"])
        metadata = self.packages["netd"]["package_metadata"]
        self.assertEqual(
            metadata["sd_overrides"],
            {"var/state/netd": "O:SYG:SYD:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"},
        )
        self.assertEqual(self.files["netd"]["var/state/netd"], {"dir": True})
        self.assertFalse(any(path.startswith("var/state/netd/") for path in self.files["netd"]))
        self.assertNotIn("signing", metadata)
        client = self.packages["net"]["package_metadata"]
        self.assertNotIn("dev.peios.netd", client["dependencies"])
        self.assertEqual(client["dependencies"]["dev.peios.libnetd"], "= 0.1.8-1")
        self.assertFalse(
            any(path.startswith(("var/", "usr/share/regim/")) for path in self.files["net"])
        )

    def test_public_library_and_debug_payloads(self) -> None:
        development = self.files["libnetd-devel"]
        self.assertEqual(
            development["usr/lib/x86_64-linux-peios/libnetd.so"], {"symlink": "libnetd.so.1"}
        )
        for path in [
            "usr/include/peios/netd.h",
            "usr/include/peios/netd-types.h",
            "usr/lib/x86_64-linux-peios/pkgconfig/netd.pc",
            "usr/share/man/man3/libnetd.3.gz",
        ]:
            self.assertIn(path, development)
        for name in ["netd", "net", "libnetd"]:
            debug = name + "-debuginfo"
            files = self.files[debug]
            self.assertEqual(sum(path.endswith(".debug") for path in files), 1)
            self.assertEqual(
                self.packages[debug]["package_metadata"]["dependencies"],
                {"dev.peios." + name: "= 0.1.8-1"},
            )
        for name, files in self.files.items():
            if name.endswith("-source"):
                continue
            for path, metadata in files.items():
                if metadata.get("exec"):
                    self.assertIn(
                        path,
                        {"usr/sbin/netd", "usr/bin/net", "usr/lib/x86_64-linux-peios/libnetd.so.1"},
                    )
                if "symlink" in metadata:
                    self.assertEqual(
                        (name, path), ("libnetd-devel", "usr/lib/x86_64-linux-peios/libnetd.so")
                    )

    def test_documentation_and_rebuildable_source(self) -> None:
        for path in [
            "usr/share/regim/netd-service.reg",
            "usr/share/regim/netd-default-profile.reg",
            "usr/share/regman/netd.regman",
            "usr/share/evman/netd.evman",
            "usr/share/man/man8/netd.8.gz",
        ]:
            self.assertIn(path, self.files["netd"])
        source = self.files["netd-source"]
        for path in [
            "Cargo.lock",
            "Cargo.toml",
            "MODULE.bazel",
            "bazel",
            "netd/src/main.rs",
            "libnetd/include/peios/netd.h",
            "vendor/kernel/ORIGIN.json",
            "vendor/ppk/src/lib.rs",
            "packages/stage.py",
        ]:
            self.assertIn("usr/src/netd/" + path, source)
        for path in source:
            self.assertFalse(
                {".git", ".trail-cache", "__pycache__", "target", "out", "archive"}
                & set(Path(path).parts),
                path,
            )


if __name__ == "__main__":
    unittest.main()
