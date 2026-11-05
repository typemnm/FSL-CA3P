"""Bounded HWP v5 reader worker. Invoked by hwp.py, never by document content."""

from __future__ import annotations

import hashlib
import json
import logging
import struct
import sys
import zlib
from contextlib import closing
from pathlib import Path

from .hwpx import MAX_ENTRIES, MAX_PART_BYTES, MAX_UNPACKED_BYTES


def inspect_hwp(source, ole_module):
    streams, total = [], 0
    with ole_module.OleFileIO(str(source)) as archive:
        paths = archive.listdir()
        if len(paths) > MAX_ENTRIES:
            raise ValueError("HWP stream count exceeds extraction limits")
        header = archive.openstream("FileHeader").read(257)
        if len(header) != 256 or not header.startswith(b"HWP Document File\0"):
            raise ValueError("not a supported HWP v5 document")
        version = tuple(reversed(header[32:36]))
        if version[0] != 5:
            raise ValueError("only HWP v5 is supported")
        flags = struct.unpack_from("<I", header, 36)[0]
        if flags & ((1 << 1) | (1 << 2) | (1 << 4) | (1 << 8) | (1 << 10)):
            raise ValueError(
                "암호·배포용·DRM HWP는 지원하지 않습니다. 접근 제한을 해제하지 않습니다."
            )
        for parts in paths:
            size = archive.get_size(parts)
            if size > MAX_PART_BYTES:
                raise ValueError("HWP stream exceeds the 16 MB limit")
            raw = archive.openstream(parts).read(MAX_PART_BYTES + 1)
            name = "/".join(parts)
            total += len(raw)
            if flags & 1 and (name == "DocInfo" or name.startswith("BodyText/")):
                decoder = zlib.decompressobj(-15)
                decoded = decoder.decompress(raw, MAX_PART_BYTES + 1)
                if len(decoded) > MAX_PART_BYTES or decoder.unconsumed_tail or not decoder.eof:
                    raise ValueError("HWP compressed section exceeds limits or is incomplete")
                total += len(decoded)
            if total > MAX_UNPACKED_BYTES:
                raise ValueError("HWP expanded streams exceed the 96 MB limit")
            streams.append(
                {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            )
    return {"version": ".".join(map(str, version)), "flags": flags, "streams": streams}


def main(argv=None):
    source, directory = map(Path, argv or sys.argv[1:])
    logging.disable(logging.CRITICAL)
    try:
        try:
            import olefile
            from hwp5.xmlmodel import Hwp5File
        except ImportError as exc:
            raise ValueError(
                'HWP 읽기 구성요소가 없습니다. 같은 Python 환경에서 pip install -e ".[hwp]"'
                " 명령으로 설치하세요."
            ) from exc
        metadata = inspect_hwp(source, olefile)
        total = 0
        with closing(Hwp5File(str(source))) as document:
            with (directory / "reader.xml").open("xb") as stream:
                for chunk in document.xmlevents().bytechunks():
                    total += len(chunk)
                    if total > MAX_UNPACKED_BYTES:
                        raise ValueError("HWP structured XML exceeds the 96 MB limit")
                    stream.write(chunk)
        (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        return 0
    except Exception as exc:
        # The parent exposes a bounded error, not a partial or apparently empty report.
        (directory / "error.json").write_text(
            json.dumps({"error": f"{type(exc).__name__}: {str(exc)[:2000]}"}, ensure_ascii=False),
            encoding="utf-8",
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
