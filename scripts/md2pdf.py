#!/usr/bin/env python3
"""
Render a lab Markdown file to a nicely styled PDF using headless Chromium.

Usage:
    python3 scripts/md2pdf.py labs/lab01.md docs/Lab01.pdf

Screenshots referenced with relative paths (e.g. ../screenshots/foo.png)
are inlined as base64 so the PDF is fully self-contained.
"""
import sys
import os
import base64
import re
import markdown
from playwright.sync_api import sync_playwright

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"

CSS = """
@page { margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
       color:#1a1a2e; line-height:1.55; font-size:12.5px; }
h1 { color:#0b3d91; border-bottom:3px solid #0b3d91; padding-bottom:.3rem;
     font-size:24px; }
h2 { color:#0b3d91; margin-top:1.6rem; border-bottom:1px solid #cdd6f4;
     padding-bottom:.2rem; font-size:18px; }
h3 { color:#12306e; font-size:15px; margin-top:1.2rem; }
code { background:#eef1fb; padding:.1rem .35rem; border-radius:4px;
       font-family:'SF Mono',Consolas,monospace; font-size:11.5px; color:#8a1f6b; }
pre { background:#0d1330; color:#e6e6f0; padding:.9rem 1rem; border-radius:8px;
      font-size:10.5px; line-height:1.45;
      white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; }
pre code { background:none; color:inherit; padding:0;
           white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; }
blockquote { border-left:4px solid #0b3d91; background:#f2f5ff; margin:1rem 0;
             padding:.6rem 1rem; border-radius:0 6px 6px 0; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:11.5px; }
th,td { border:1px solid #c9d2ee; padding:.45rem .6rem; text-align:left; }
th { background:#0b3d91; color:#fff; }
tr:nth-child(even){ background:#f6f8ff; }
img { max-width:100%; border:1px solid #ccc; border-radius:6px; margin:.6rem 0;
      box-shadow:0 2px 8px rgba(0,0,0,.12); }
.theory { background:#fff8e6; border:1px solid #f0d68c; border-radius:8px;
          padding:.4rem 1rem; margin:1rem 0; }
.why { background:#e8f7ee; border:1px solid #8fd6a8; border-radius:8px;
       padding:.4rem 1rem; margin:1rem 0; }
hr { border:0; border-top:1px solid #ccc; margin:1.5rem 0; }
a { color:#0b3d91; }
"""


def inline_images(html, base_dir):
    def repl(m):
        src = m.group(1)
        if src.startswith("data:") or src.startswith("http"):
            return m.group(0)
        path = os.path.normpath(os.path.join(base_dir, src))
        if not os.path.exists(path):
            return m.group(0)
        ext = os.path.splitext(path)[1].lstrip(".") or "png"
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        return m.group(0).replace(src, f"data:image/{ext};base64,{b64}")

    return re.sub(r'<img[^>]*src="([^"]+)"', repl, html)


def main():
    src, out = sys.argv[1], sys.argv[2]
    base_dir = os.path.dirname(os.path.abspath(src))
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()
    body = markdown.markdown(
        text, extensions=["fenced_code", "tables", "codehilite", "toc"]
    )
    body = inline_images(body, base_dir)
    doc = f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style>"
    doc += f"</head><body>{body}</body></html>"

    tmp = out + ".html"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(doc)

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = browser.new_page()
        page.goto("file://" + os.path.abspath(tmp), wait_until="networkidle")
        page.pdf(path=out, format="A4", print_background=True,
                 margin={"top": "0", "bottom": "0", "left": "0", "right": "0"})
        browser.close()
    os.remove(tmp)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
