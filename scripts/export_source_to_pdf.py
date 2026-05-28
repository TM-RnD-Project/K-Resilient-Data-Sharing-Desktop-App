#!/usr/bin/env python3
"""Export application source files to a copyright-registration PDF."""

from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PDF = PROJECT_ROOT / "copyright_source_code.pdf"
OUTPUT_FILE_LIST = PROJECT_ROOT / "copyright_source_file_list.txt"

INCLUDE_GLOBS = [
    "src/**/*.jsx",
    "src/**/*.js",
    "src/**/*.css",
    "src-tauri/src/**/*.rs",
    "src-tauri/src/bin/**/*.rs",
]

INCLUDE_FILES = [
    "src-tauri/Cargo.toml",
    "package.json",
    "tauri.conf.json",
    "src-tauri/tauri.conf.json",
    "vite.config.js",
]

EXCLUDED_DIRS = {
    ".git",
    "benchmark_results",
    "dataset",
    "dist",
    "node_modules",
    "target",
}

EXCLUDED_FILES = {
    "Cargo.lock",
    "package-lock.json",
}

EXCLUDED_SUMMARY = [
    "src-tauri/mcore/**",
    "node_modules/**",
    "target/**",
    "dist/**",
    "dataset/**",
    "benchmark_results/**",
    ".git/**",
    "package-lock.json",
    "Cargo.lock",
]


def require_reportlab():
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen import canvas

        return colors, A4, pdfmetrics, TTFont, canvas
    except ImportError:
        print("ReportLab is required to generate the PDF.")
        print("Install it with:")
        print("  pip install reportlab")
        sys.exit(1)


def rel_path(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def is_excluded(path: Path) -> bool:
    relative = path.relative_to(PROJECT_ROOT)
    parts = relative.parts

    if path.name in EXCLUDED_FILES:
        return True

    if any(part in EXCLUDED_DIRS for part in parts):
        return True

    return len(parts) >= 2 and parts[0] == "src-tauri" and parts[1] == "mcore"


def collect_source_files() -> list[Path]:
    found: dict[str, Path] = {}

    for pattern in INCLUDE_GLOBS:
        for path in PROJECT_ROOT.glob(pattern):
            if path.is_file() and not is_excluded(path):
                found[rel_path(path)] = path

    for relative_name in INCLUDE_FILES:
        path = PROJECT_ROOT / relative_name
        if path.is_file() and not is_excluded(path):
            found[rel_path(path)] = path

    return [found[name] for name in sorted(found)]


def write_file_list(files: list[Path]) -> None:
    lines = [
        "Copyright Source File List",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Total files: {len(files)}",
        "",
    ]
    lines.extend(rel_path(path) for path in files)
    OUTPUT_FILE_LIST.write_text("\n".join(lines) + "\n", encoding="utf-8")


def project_title() -> str:
    package_json = PROJECT_ROOT / "package.json"
    fallback = "K-Resilient Data Sharing Desktop App"

    if not package_json.is_file():
        return fallback

    try:
        package_data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback

    name = str(package_data.get("name", "")).strip()
    if not name:
        return fallback

    return name.replace("-", " ").replace("_", " ").title()


def register_monospace_font(pdfmetrics, TTFont) -> tuple[str, bool]:
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = [
        windir / "Fonts" / "consola.ttf",
        windir / "Fonts" / "cour.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        Path("/usr/share/fonts/dejavu/DejaVuSansMono.ttf"),
        Path("/Library/Fonts/Menlo.ttc"),
    ]

    for font_path in candidates:
        if font_path.is_file():
            try:
                pdfmetrics.registerFont(TTFont("SourceCodeMono", str(font_path)))
                return "SourceCodeMono", True
            except Exception:
                continue

    return "Courier", False


def safe_text(text: str, unicode_font_available: bool) -> str:
    if unicode_font_available:
        return text
    return text.encode("latin-1", errors="replace").decode("latin-1")


def wrap_text_to_width(
    text: str,
    max_width: float,
    font_name: str,
    font_size: float,
    pdfmetrics,
) -> list[str]:
    if text == "":
        return [""]

    wrapped: list[str] = []
    current = ""

    for char in text:
        candidate = current + char
        if current and pdfmetrics.stringWidth(candidate, font_name, font_size) > max_width:
            wrapped.append(current)
            current = char
        else:
            current = candidate

    wrapped.append(current)
    return wrapped


def source_lines(
    path: Path,
    max_width: float,
    font_name: str,
    font_size: float,
    pdfmetrics,
    unicode_font_available: bool,
) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace").expandtabs(4)
    lines: list[str] = []

    for raw_line in text.splitlines():
        line = safe_text(raw_line.rstrip("\n\r"), unicode_font_available)
        lines.extend(wrap_text_to_width(line, max_width, font_name, font_size, pdfmetrics))

    return lines or [""]


def chunk_lines(lines: list[str], first_page_capacity: int, page_capacity: int) -> list[list[str]]:
    chunks: list[list[str]] = []
    index = 0

    first_chunk = lines[:first_page_capacity]
    chunks.append(first_chunk)
    index += len(first_chunk)

    while index < len(lines):
        chunk = lines[index : index + page_capacity]
        chunks.append(chunk)
        index += len(chunk)

    return chunks


def build_pages(files: list[Path], page_size, pdfmetrics, font_name: str, unicode_font_available: bool):
    width, height = page_size
    margin_x = 42
    top = height - 48
    bottom = 44
    code_size = 7.2
    code_leading = 8.8
    heading_space = 38
    max_code_width = width - (2 * margin_x)
    page_capacity = math.floor((top - bottom) / code_leading)
    first_page_capacity = math.floor((top - heading_space - bottom) / code_leading)

    pages = [{"kind": "cover"}]

    toc_lines = [f"{index}. {rel_path(path)}" for index, path in enumerate(files, 1)]
    toc_capacity = 44
    for index in range(0, len(toc_lines), toc_capacity):
        pages.append({"kind": "toc", "lines": toc_lines[index : index + toc_capacity]})

    for path in files:
        lines = source_lines(
            path,
            max_code_width,
            font_name,
            code_size,
            pdfmetrics,
            unicode_font_available,
        )
        chunks = chunk_lines(lines, first_page_capacity, page_capacity)

        for chunk_index, chunk in enumerate(chunks):
            pages.append(
                {
                    "kind": "source",
                    "path": rel_path(path),
                    "lines": chunk,
                    "continued": chunk_index > 0,
                }
            )

    return pages


def draw_footer(pdf, page_number: int, total_pages: int, width: float) -> None:
    pdf.setFont("Helvetica", 8)
    pdf.setFillColorRGB(0.35, 0.35, 0.35)
    pdf.drawCentredString(width / 2, 24, f"Page {page_number} of {total_pages}")


def draw_pdf(files: list[Path]) -> int:
    colors, A4, pdfmetrics, TTFont, canvas = require_reportlab()
    font_name, unicode_font_available = register_monospace_font(pdfmetrics, TTFont)
    pages = build_pages(files, A4, pdfmetrics, font_name, unicode_font_available)

    width, height = A4
    margin_x = 42
    pdf = canvas.Canvas(str(OUTPUT_PDF), pagesize=A4)
    title = project_title()
    total_pages = len(pages)

    for page_number, page in enumerate(pages, 1):
        kind = page["kind"]

        if kind == "cover":
            pdf.setFillColor(colors.black)
            pdf.setFont("Helvetica-Bold", 22)
            pdf.drawCentredString(width / 2, height - 210, title)
            pdf.setFont("Helvetica", 16)
            pdf.drawCentredString(width / 2, height - 238, "Source Code Submission")
            pdf.setFont("Helvetica", 11)
            pdf.drawCentredString(width / 2, height - 280, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            pdf.drawCentredString(width / 2, height - 300, f"Included source files: {len(files)}")

        elif kind == "toc":
            pdf.setFillColor(colors.black)
            pdf.setFont("Helvetica-Bold", 16)
            pdf.drawString(margin_x, height - 54, "Table of Contents / Included Files")
            pdf.setFont("Helvetica", 9)
            y = height - 82
            for line in page["lines"]:
                pdf.drawString(margin_x, y, safe_text(line, unicode_font_available))
                y -= 15

        elif kind == "source":
            heading = page["path"]
            if page["continued"]:
                heading = f"{heading} (continued)"

            pdf.setFillColor(colors.black)
            pdf.setFont("Helvetica-Bold", 11)
            pdf.drawString(margin_x, height - 42, safe_text(heading, unicode_font_available))

            pdf.setFont(font_name, 7.2)
            y = height - 72 if not page["continued"] else height - 54
            for line in page["lines"]:
                pdf.drawString(margin_x, y, line)
                y -= 8.8

        draw_footer(pdf, page_number, total_pages, width)
        pdf.showPage()

    pdf.save()
    return total_pages


def main() -> int:
    files = collect_source_files()
    if not files:
        print("No source files matched the configured include rules.")
        return 1

    write_file_list(files)
    total_pages = draw_pdf(files)

    print(f"Total number of files included: {len(files)}")
    print(f"Total number of pages: {total_pages}")
    print(f"Output PDF path: {OUTPUT_PDF}")
    print(f"Source file list path: {OUTPUT_FILE_LIST}")
    print("Excluded folders summary:")
    for item in EXCLUDED_SUMMARY:
        print(f"  - {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
