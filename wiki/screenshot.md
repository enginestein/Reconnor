# Website Screenshot

Full-page website screenshot tool using Playwright (headless Chromium). Configurable viewport size, full-page capture, and custom output directory. Falls back to HTTP status check if Playwright is not installed.

```
python3 main.py screenshot https://example.com
python3 main.py screenshot https://example.com --output-dir reports --full-page
python3 main.py screenshot https://example.com --width 1920 --height 1080
```

**Options:**
- `--output-dir` -- Output directory for screenshots (default: screenshots)
- `--width` -- Viewport width in pixels (default: 1280)
- `--height` -- Viewport height in pixels (default: 720)
- `--full-page` -- Capture full page (scrolling), not just viewport
- `--delay` -- Delay before capture in seconds
- `--timeout` -- Navigation timeout in seconds (default: 30)

**How it works:** Launches Playwright's headless Chromium browser, navigates to the target URL, waits for network idle, and captures a screenshot. Filenames are derived from the target domain. Requires `pip install playwright && playwright install chromium` for full functionality.
