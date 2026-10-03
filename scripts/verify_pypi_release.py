#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import time
from pathlib import Path
from typing import Any


PROJECT = "repo-assurance"
INDEX_ENDPOINTS = {
    "pypi": ("pypi.org", "/pypi/{project}/{version}/json"),
    "testpypi": ("test.pypi.org", "/pypi/{project}/{version}/json"),
}


def local_distribution_hashes(release_dir: Path) -> dict[str, str]:
    wheel = sorted(release_dir.glob("repo_assurance-*.whl"))
    sdist = sorted(release_dir.glob("repo_assurance-*.tar.gz"))
    if len(wheel) != 1 or len(sdist) != 1:
        raise ValueError(
            "expected exactly one repo_assurance wheel and one source distribution"
        )

    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [*wheel, *sdist]
    }


def published_distribution_hashes(payload: dict[str, Any]) -> dict[str, str]:
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        raise ValueError("package index response contains no distribution files")

    hashes: dict[str, str] = {}
    for item in urls:
        if not isinstance(item, dict):
            raise ValueError("package index response contains an invalid file entry")
        filename = item.get("filename")
        digests = item.get("digests")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(filename, str) or not isinstance(sha256, str):
            raise ValueError("package index file entry is missing filename or sha256")
        hashes[filename] = sha256
    return hashes


def require_matching_hashes(
    local_hashes: dict[str, str],
    published_hashes: dict[str, str],
) -> None:
    if set(local_hashes) != set(published_hashes):
        raise ValueError(
            "published distribution filenames do not exactly match validated artifacts: "
            f"local={sorted(local_hashes)} published={sorted(published_hashes)}"
        )

    mismatches = [
        name
        for name, digest in local_hashes.items()
        if published_hashes.get(name) != digest
    ]
    if mismatches:
        raise ValueError(
            "published distribution SHA-256 mismatch for: "
            + ", ".join(sorted(mismatches))
        )


def fetch_index_payload(
    index: str,
    version: str,
    *,
    attempts: int = 24,
    delay_seconds: float = 5.0,
) -> dict[str, Any]:
    host, path_template = INDEX_ENDPOINTS[index]
    path = path_template.format(project=PROJECT, version=version)

    last_error: Exception | None = None
    retryable_statuses = {404, 429, 500, 502, 503, 504}
    for attempt in range(1, attempts + 1):
        connection = http.client.HTTPSConnection(host, timeout=15)
        try:
            connection.request(
                "GET",
                path,
                headers={"User-Agent": "repo-assurance-release-verifier/1"},
            )
            response = connection.getresponse()
            body = response.read()
            if response.status == 200:
                payload = json.loads(body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError(
                        "package index returned a non-object JSON payload"
                    )
                return payload
            if response.status not in retryable_statuses:
                raise RuntimeError(
                    f"{index} returned HTTP {response.status} for {PROJECT}=={version}"
                )
            last_error = RuntimeError(
                f"{index} returned retryable HTTP {response.status}"
            )
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()

        if attempt != attempts:
            time.sleep(delay_seconds)

    raise RuntimeError(
        f"{index} metadata for {PROJECT}=={version} did not become available"
    ) from last_error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify published PyPI/TestPyPI files against validated artifacts."
    )
    parser.add_argument("--index", choices=sorted(INDEX_ENDPOINTS), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    local_hashes = local_distribution_hashes(args.release_dir)
    payload = fetch_index_payload(args.index, args.version)
    published_hashes = published_distribution_hashes(payload)
    require_matching_hashes(local_hashes, published_hashes)
    print(
        f"verified {len(local_hashes)} distributions for "
        f"{PROJECT}=={args.version} on {args.index}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
