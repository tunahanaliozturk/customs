"""The benign corpus: the most downloaded packages on nuget.org.

    python corpus/corpus.py list [--count 300]   writes corpus/benign.txt
    python corpus/corpus.py fetch [--dir DIR]    downloads what benign.txt pins

`list` asks the nuget.org search API for the most downloaded packages,
downloads each latest stable version once and pins its SHA-512. `fetch`
downloads the pinned versions into DIR (default target/corpus, which git
ignores) and checks every file against its pinned hash; a mismatch is an
error and the file is not kept. Only nuget.org over HTTPS is contacted.
Standard library only.
"""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIST = ROOT / "corpus" / "benign.txt"
SERVICE_INDEX = "https://api.nuget.org/v3/index.json"
FLAT_CONTAINER = "https://api.nuget.org/v3-flatcontainer/"
# The order is by total downloads. `sortBy=totalDownloads-desc` is not in
# the documentation; on 2026-11-22 it gave the same first results as the
# default order without a query. The list records the exact query.
QUERY = {
    "q": "",
    "prerelease": "false",
    "semVerLevel": "2.0.0",
    "sortBy": "totalDownloads-desc",
}


def get(url):
    if not url.startswith("https://"):
        raise SystemExit(f"refusing a URL that is not HTTPS: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "customs-corpus"})
    with urllib.request.urlopen(request, timeout=120) as response:
        if not response.geturl().startswith("https://"):
            raise SystemExit(f"redirected away from HTTPS: {response.geturl()}")
        return response.read()


def nupkg_url(package_id, version):
    # The flat container names versions without build metadata. The ID and
    # version come from the search API, so they are percent-encoded.
    lower_id = urllib.parse.quote(package_id.lower(), safe="")
    lower_version = urllib.parse.quote(version.split("+")[0].lower(), safe="")
    return f"{FLAT_CONTAINER}{lower_id}/{lower_version}/{lower_id}.{lower_version}.nupkg"


def file_name(package_id, version):
    return f"{package_id.lower()}.{version.split('+')[0].lower()}.nupkg"


def sha512(data):
    return base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def read_list():
    entries = []
    for line in LIST.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            package_id, version, digest = line.split()
            entries.append((package_id, version, digest))
    return entries


def search_url(count):
    index = json.loads(get(SERVICE_INDEX))
    search = next(
        r["@id"] for r in index["resources"] if r["@type"].startswith("SearchQueryService")
    )
    return search + "?" + urllib.parse.urlencode({**QUERY, "skip": 0, "take": count})


def command_list(args):
    url = search_url(args.count)
    results = json.loads(get(url))["data"]
    directory = pathlib.Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)

    def pin(result):
        data = get(nupkg_url(result["id"], result["version"]))
        (directory / file_name(result["id"], result["version"])).write_bytes(data)
        return result["id"], result["version"], sha512(data)

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        pinned = list(pool.map(pin, results))
    today = datetime.date.today().isoformat()
    lines = [
        "# The benign corpus: the most downloaded packages on nuget.org, latest stable versions.",
        f"# Made by `python corpus/corpus.py list --count {args.count}` on {today}.",
        f"# Query: {url}",
        "# Columns: ID, version, SHA-512 of the .nupkg in base64.",
    ]
    lines += [f"{package_id} {version} {digest}" for package_id, version, digest in pinned]
    LIST.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"pinned {len(pinned)} packages in {LIST.relative_to(ROOT)}")


def command_fetch(args):
    directory = pathlib.Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)

    def fetch(entry):
        package_id, version, digest = entry
        target = directory / file_name(package_id, version)
        if target.exists() and sha512(target.read_bytes()) == digest:
            return 0
        data = get(nupkg_url(package_id, version))
        if sha512(data) != digest:
            raise SystemExit(f"{package_id} {version}: SHA-512 does not match the pinned value")
        partial = target.with_suffix(".part")
        partial.write_bytes(data)
        os.replace(partial, target)
        return len(data)

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        sizes = list(pool.map(fetch, read_list()))
    listed = [directory / file_name(package_id, version) for package_id, version, _ in read_list()]
    total = sum(path.stat().st_size for path in listed)
    print(
        f"{len(sizes)} packages in {directory}, {sum(1 for s in sizes if s)} downloaded, "
        f"{total:,} bytes in all"
    )


def count(text):
    """A package count the search API accepts in one query."""
    value = int(text)
    if not 1 <= value <= 1000:
        raise argparse.ArgumentTypeError("the count must be from 1 to 1000")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("list", help="query nuget.org and pin the list")
    make.add_argument("--count", type=count, default=300)
    make.add_argument("--dir", default=str(ROOT / "target" / "corpus"))
    fetch = commands.add_parser("fetch", help="download and check the pinned packages")
    fetch.add_argument("--dir", default=str(ROOT / "target" / "corpus"))
    args = parser.parse_args()
    {"list": command_list, "fetch": command_fetch}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
