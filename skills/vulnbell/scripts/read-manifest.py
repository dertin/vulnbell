"""Read an authorized JSON, TOML or XML manifest as data and paginate its values."""

import argparse
import itertools
import json
import os
from pathlib import Path
import stat
import sys
import xml.etree.ElementTree as ET

PRIVATE_NAMES = {
    ".git", ".ssh", ".aws", ".kube", ".gnupg", ".config",
    ".docker", ".azure", ".gcloud", ".npmrc", ".yarnrc", ".yarnrc.yml",
    ".git-credentials", ".dockercfg", ".netrc", ".pypirc",
    "credentials", "credentials.json", "credentials.toml", "nuget.config", "auth.json",
}


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def xml_value(element):
    return {
        "tag": element.tag,
        "attributes": element.attrib,
        "text": (element.text or "").strip(),
        "children": [xml_value(child) for child in element],
    }


def leaves(value, pointer=""):
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from leaves(child, pointer + "/" + escaped)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, pointer + "/" + str(index))
    else:
        yield {"pointer": pointer, "value": value}


def read(root, relative, format_name, offset, limit):
    if offset < 0 or not 1 <= limit <= 1000:
        raise ValueError("offset must be nonnegative and limit must be 1..1000")
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("select a relative path inside the authorized workspace")
    root = root.resolve(strict=True)
    path = root
    for part in relative.parts:
        name = part.lower()
        if (
            name in PRIVATE_NAMES
            or name == ".env"
            or name.startswith(".env.")
            or name.endswith((".pem", ".key", ".p12", ".pfx"))
        ):
            raise ValueError("private path excluded")
        path /= part
        if path.is_symlink():
            raise ValueError("symlinks are excluded")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("input must be a regular file")
        content = source.read(16 * 1024 * 1024 + 1)
    if len(content) > 16 * 1024 * 1024:
        raise ValueError("manifest exceeds this helper's 16 MiB budget; retain partial coverage and use chunked discovery or a reviewed streaming parser")
    text = content.decode("utf-8")
    if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
        raise ValueError("private key material excluded")
    if format_name == "json":
        data = json.loads(text, object_pairs_hook=pairs)
    elif format_name == "toml":
        import tomllib

        data = tomllib.loads(text)
    else:
        if "<!doctype" in text.lower() or "<!entity" in text.lower():
            raise ValueError("XML DTDs and entities are excluded")
        data = xml_value(ET.fromstring(text))
    values = list(itertools.islice(leaves(data), offset, offset + limit + 1))
    return {"format": format_name, "offset": offset, "values": values[:limit], "next_offset": offset + limit if len(values) > limit else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--format", required=True, choices=["json", "toml", "xml"])
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    try:
        result = read(args.root, args.file, args.format, args.offset, args.limit)
        print(json.dumps(result, ensure_ascii=True, default=str))
    except (OSError, ValueError, RecursionError, ImportError, ET.ParseError):
        print(json.dumps({"error": "manifest parsing unavailable; keep coverage partial; inspect format, path, parser budget and Python version (TOML requires 3.11+)"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
