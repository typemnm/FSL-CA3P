"""Build a standalone local review page without DB access or external assets."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from zipfile import BadZipFile, ZipFile

from .hwpx import MAX_FILE_BYTES, MAX_PART_BYTES
from .import_workflow import ReportReview, digest, review_template
from .report_drafts import ReportDraft

IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}


def render_hwpx_review(
    report: ReportDraft,
    *,
    source_hwpx: Path | None = None,
    review: ReportReview | None = None,
) -> str:
    """Render text as data; embed only hash-verified raster images from the source."""
    review = review or review_template(report)
    if review.report_sha256 != report.source["sha256"] or review.draft_sha256 != digest(report):
        raise ValueError("review belongs to a different report or extraction revision")
    images = {}
    if source_hwpx is not None:
        if source_hwpx.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("source HWPX exceeds the 32 MB limit")
        body = source_hwpx.read_bytes()
        if len(body) > MAX_FILE_BYTES:
            raise ValueError("source HWPX exceeds the 32 MB limit")
        if hashlib.sha256(body).hexdigest() != report.source.get("sha256"):
            raise ValueError("review source HWPX does not match draft SHA-256")
        try:
            with ZipFile(BytesIO(body)) as archive:
                for item in report.document.get("images", []):
                    if not item.get("embedded") or item.get("media_type") not in IMAGE_TYPES:
                        continue
                    part = item.get("archive_part", "")
                    if archive.getinfo(part).file_size > MAX_PART_BYTES:
                        raise ValueError("review image exceeds extraction size limits")
                    data = archive.read(part)
                    if hashlib.sha256(data).hexdigest() != item.get("sha256"):
                        raise ValueError("review image does not match draft SHA-256")
                    encoded = base64.b64encode(data).decode("ascii")
                    images[item["image_id"]] = f"data:{item['media_type']};base64,{encoded}"
        except (BadZipFile, KeyError, RuntimeError) as exc:
            raise ValueError("review source image archive is not readable") from exc
    bundle = (
        json.dumps(
            {
                "report": report.model_dump(mode="json"),
                "images": images,
                "review": review.model_dump(mode="json"),
            },
            ensure_ascii=True,
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    assets = files("casper_db").joinpath("review_assets")
    return (
        assets.joinpath("index.html")
        .read_text(encoding="utf-8")
        .replace("@@NONCE@@", secrets.token_urlsafe(18))
        .replace("@@STYLE@@", assets.joinpath("review.css").read_text(encoding="utf-8"))
        .replace("@@SCRIPT@@", assets.joinpath("review.js").read_text(encoding="utf-8"))
        .replace("@@DATA@@", bundle)
    )


def make_review_server(page: Path, *, port: int = 8765) -> ThreadingHTTPServer:
    """Serve one generated page on loopback; expose no files, listings, or write API."""
    page = page.resolve(strict=True)
    if not page.is_file() or page.suffix.lower() != ".html":
        raise ValueError("review page must be an existing .html file")
    if not 0 <= port <= 65535:
        raise ValueError("review port must be between 0 and 65535")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self._page(include_body=True)

        def do_HEAD(self):
            self._page(include_body=False)

        def _page(self, *, include_body: bool):
            if urlsplit(self.path).path not in {"/", "/index.html"}:
                self.send_error(404)
                return
            try:
                data = page.read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if include_body:
                self.wfile.write(data)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
