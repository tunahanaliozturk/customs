"""The popular package IDs that rules C402 and C403 compare against.

    python data/popular.py

writes data/popular-ids.txt, sorted ignoring case, with the date and the
queries in the header. customs embeds that file when it is built; the tool
itself never fetches it. Two steps:

1. The 4,000 most downloaded IDs from the nuget.org search API with an empty
   query, in four pages of 1,000 (the API allows `skip` up to 3,000 and
   `take` up to 1,000).
2. An empty query is nuget.org's "default search", which leaves out the
   packages on its list of packages excluded by default, such as xunit.core
   with over a billion downloads (NuGet.Services.AzureSearch,
   SearchParametersBuilder.cs). A query by owner is not a default search.
   So for every owner of a step-1 ID, the script asks for that owner's
   packages by downloads and adds every ID with at least as many total
   downloads as the last ID of step 1.

`sortBy=totalDownloads-desc` is not in the API's documentation, so the
script also fetches the step-1 pages without it and prints how many IDs and
positions the two orders share, and how often a result has more reported
`totalDownloads` than the one before it. Only nuget.org over HTTPS is
contacted. Standard library only.
"""

import concurrent.futures
import datetime
import json
import pathlib
import sys
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "popular-ids.txt"
SERVICE_INDEX = "https://api.nuget.org/v3/index.json"
PAGE = 1000
PAGES = 4
QUERY = {
    "q": "",
    "prerelease": "true",
    "semVerLevel": "2.0.0",
    "sortBy": "totalDownloads-desc",
}


def get(url, tries=4):
    if not url.startswith("https://"):
        raise SystemExit(f"refusing a URL that is not HTTPS: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "customs-popular-ids"})
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                if not response.geturl().startswith("https://"):
                    raise SystemExit(f"redirected away from HTTPS: {response.geturl()}")
                return json.loads(response.read())
        except (OSError, json.JSONDecodeError):
            # The search service resets a connection now and then under a
            # few hundred queries; wait and ask again.
            if attempt == tries - 1:
                raise
            time.sleep(2 ** attempt)


def search_base():
    index = get(SERVICE_INDEX)
    return next(
        r["@id"] for r in index["resources"] if r["@type"].startswith("SearchQueryService")
    )


def page(base, query, skip):
    url = base + "?" + urllib.parse.urlencode({**query, "skip": skip, "take": PAGE})
    return url, get(url)["data"]


def fetch(base, query):
    urls, results = [], []
    for number in range(PAGES):
        url, data = page(base, query, number * PAGE)
        if len(data) != PAGE:
            raise SystemExit(f"{url}: {len(data)} results, expected {PAGE}")
        urls.append(url)
        results += data
    return urls, results


def owners(result):
    names = result.get("owners") or []
    return [names] if isinstance(names, str) else names


def by_owner(base, owner, floor):
    """The owner's IDs with at least `floor` total downloads, and whether
    the API's paging limit cut the list short."""
    found = []
    for number in range(PAGES):
        _, data = page(base, {**QUERY, "q": f"owner:{owner}"}, number * PAGE)
        found += [r["id"] for r in data if r["totalDownloads"] >= floor]
        if len(data) < PAGE or data[-1]["totalDownloads"] < floor:
            return found, False
    return found, True


def main():
    base = search_base()
    urls, results = fetch(base, QUERY)
    _, default = fetch(base, {k: v for k, v in QUERY.items() if k != "sortBy"})
    ids = {}
    for result in results:
        # The order of pages can shift while they are fetched; the first
        # spelling of an ID wins and a repeat is dropped.
        ids.setdefault(result["id"].lower(), result["id"])
    first = len(ids)
    downloads = [r["totalDownloads"] for r in results]
    # The last of them, not the fewest: a result whose downloads were
    # transferred to it by nuget.org can rank in the first 4,000 with far
    # fewer downloads of its own (300,768 on 2026-11-25).
    floor = downloads[-1]
    all_owners = sorted({o for r in results for o in owners(r)}, key=str.lower)
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        per_owner = list(pool.map(lambda o: by_owner(base, o, floor), all_owners))
    cut = [o for o, (_, short) in zip(all_owners, per_owner) if short]
    for found, _ in per_owner:
        for package_id in found:
            ids.setdefault(package_id.lower(), package_id)
    rises = sum(1 for a, b in zip(downloads, downloads[1:]) if b > a)
    same_place = sum(1 for a, b in zip(results, default) if a["id"].lower() == b["id"].lower())
    shared = len({r["id"].lower() for r in results} & {r["id"].lower() for r in default})
    today = datetime.date.today().isoformat()
    lines = [
        "# The most downloaded package IDs on nuget.org, which C402 and C403 compare against.",
        f"# Made by `python data/popular.py` on {today}: {len(ids)} IDs, sorted ignoring case.",
        f"# {first} from {urls[0]} and the same with skip {PAGE}, {2 * PAGE} and {3 * PAGE};",
        f"# {len(ids) - first} more with at least {floor:,} total downloads, as many as the last of those,",
        f"# from the same query with q=owner:NAME for each of their {len(all_owners)} owners.",
    ]
    lines += sorted(ids.values(), key=str.lower)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(ids)} IDs to {OUT.relative_to(ROOT)}: {first} by default search,")
    print(f"  {len(ids) - first} more from {len(all_owners)} owners with at least {floor:,} downloads")
    print(f"owners whose list the paging limit cut short: {cut or 'none'}")
    print(f"without sortBy: {shared} of the IDs shared, {same_place} in the same place")
    print(f"{rises} of {len(results) - 1} results have more total downloads than the one before")


if __name__ == "__main__":
    sys.exit(main())
