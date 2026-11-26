from __future__ import annotations

import pathlib
import py_compile
import tempfile
import unittest

from polyscope import analyze, detect, classify


class TestContainers(unittest.TestCase):
    def test_elf(self):
        p = pathlib.Path("/bin/ls")
        if not p.exists():
            self.skipTest("no /bin/ls")
        d = detect(p.read_bytes()[:64])
        self.assertEqual(d["container"], "elf")
        self.assertEqual(d["bits"], 64)

    def test_wasm_header(self):
        d = detect(b"\x00asm\x01\x00\x00\x00")
        self.assertEqual(d["container"], "wasm")

    def test_pyc(self):
        with tempfile.TemporaryDirectory() as td:
            src = pathlib.Path(td) / "x.py"
            src.write_text("x = 1\n")
            pyc = pathlib.Path(td) / "x.pyc"
            py_compile.compile(str(src), cfile=str(pyc), doraise=True)
            d = detect(pyc.read_bytes()[:16])
            self.assertEqual(d["container"], "pyc")

    def test_unknown(self):
        d = detect(bytes(range(1, 40)))
        self.assertIn(d["container"], ("unknown", "text"))


class TestLanguages(unittest.TestCase):
    def test_text_rust(self):
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as f:
            f.write('fn main(){println!("hi");}\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "rust")
        finally:
            p.unlink()

    def test_text_go(self):
        with tempfile.NamedTemporaryFile("w", suffix=".go", delete=False) as f:
            f.write('package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "go")
        finally:
            p.unlink()

    def test_text_python(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write('def f(x):\n    return x + 1\nprint(f(2))\n'); p = pathlib.Path(f.name)
        try:
            self.assertEqual(analyze(p)["lang"], "python")
        finally:
            p.unlink()

    def test_system_binary_is_an_elf(self):
        # Which compiler produced the distribution's /bin/ls is not our claim, and it
        # changes between images (the Ubuntu 24.04 runner's ls carries a Rust marker).
        # The claim is that a real system binary is identified as an ELF and classified.
        p = pathlib.Path("/bin/ls")
        if not p.exists():
            self.skipTest("no /bin/ls")
        result = analyze(p)
        self.assertEqual(result["container"], "elf")
        self.assertIsInstance(result["lang"], str)
        self.assertTrue(result["lang"])

    def test_c_markers_classify_as_c(self):
        votes = classify(b"GLIBC_2.34 __libc_start_main", "elf",
                         strings=["__libc_start_main", "libc.so.6"], needed=["libc.so.6"])
        self.assertEqual(votes["lang"], "c")

    def test_rust_markers_classify_as_rust(self):
        votes = classify(b"rustc version /build/rustc-abc/library/std/src/", "elf",
                         strings=["rustc version", "library/std/src/"])
        self.assertEqual(votes["lang"], "rust")


class TestVotes(unittest.TestCase):
    def test_unknown_is_first_class(self):
        v = classify(b"\x01\x02\x03", "unknown")
        self.assertIsInstance(v, dict)


if __name__ == "__main__":
    unittest.main()
