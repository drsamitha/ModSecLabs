#!/usr/bin/env python3
"""
Take a screenshot of a URL (or of raw HTML) with headless Chromium.

Usage:
    python3 scripts/shoot.py <url> <out.png> [--width 900] [--tag LABEL]

If --tag is given, a small labelled bar is injected at the top of the page
so the screenshot is self-describing inside the practical sheets.
"""
import sys
import argparse
from playwright.sync_api import sync_playwright

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("out")
    ap.add_argument("--width", type=int, default=900)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": args.width, "height": 700})
        resp = page.goto(args.url, wait_until="networkidle", timeout=15000)
        status = resp.status if resp else "?"
        if args.tag:
            page.evaluate(
                """(txt) => {
                    const bar = document.createElement('div');
                    bar.textContent = txt;
                    bar.style.cssText =
                      'position:fixed;top:0;left:0;right:0;z-index:99999;'+
                      'background:#111;color:#0f0;font:13px monospace;'+
                      'padding:6px 10px;border-bottom:2px solid #0f0;';
                    document.body.style.marginTop='34px';
                    document.body.prepend(bar);
                }""",
                f"{args.tag}   [HTTP {status}]",
            )
        page.screenshot(path=args.out, full_page=True)
        browser.close()
        print(f"saved {args.out}  (HTTP {status})")


if __name__ == "__main__":
    main()
