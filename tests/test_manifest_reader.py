import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "skills/vulnbell/scripts/read-manifest.py"
SPEC = importlib.util.spec_from_file_location("manifest_reader", SCRIPT)
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)


class ManifestReaderTests(unittest.TestCase):
    def test_formats_and_pagination_preserve_all_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            examples = {
                "json": '{"dependencies":{"example":"1.2.3","second":"2.0"}}',
                "toml": '[project]\ndependencies = ["example==1.2.3", "second==2.0"]\n',
                "xml": '<Project><PackageReference Include="example" Version="1.2.3" /></Project>',
            }
            for format_name, text in examples.items():
                path = Path("manifest." + format_name)
                (root / path).write_text(text)
                offset = 0
                values = []
                while offset is not None:
                    page = READER.read(root, path, format_name, offset, 1)
                    values.extend(page["values"])
                    offset = page["next_offset"]
                self.assertTrue(any("1.2.3" in str(item["value"]) for item in values))

    def test_rejects_private_paths_traversal_and_xml_entities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text('{"secret":"SYNTHETIC_CANARY"}')
            (root / "credentials.toml").write_text('token="SYNTHETIC_CANARY"')
            (root / "manifest.xml").write_text('<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>')
            for path, format_name in [(".env", "json"), ("credentials.toml", "toml"), ("../outside.json", "json"), ("manifest.xml", "xml")]:
                with self.assertRaises(ValueError):
                    READER.read(root, Path(path), format_name, 0, 100)

    def test_rejects_duplicate_json_and_malformed_toml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for format_name, text in [("json", '{"x":1,"x":2}'), ("toml", "[broken")]:
                (root / "manifest").write_text(text)
                with self.assertRaises(ValueError):
                    READER.read(root, Path("manifest"), format_name, 0, 100)


if __name__ == "__main__":
    unittest.main()
