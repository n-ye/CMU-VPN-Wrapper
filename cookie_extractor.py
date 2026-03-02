try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("Error: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    sys.exit(1)

import time

def extract_cookies_via_browser(
    url: str,
    cookie_name: Optional[str] = None,
    timeout: int = 300,
) -> dict:
    """
    Opens a Chromium browser window for the user to log in.
    After login, extracts cookies from the browser context.

    Args:
        url: The VPN portal URL to open.
        cookie_name: Specific cookie to wait for (e.g., 'DSID', 'webvpn').
                     If None, captures all cookies after the user closes the browser.
        timeout: Max seconds to wait for login.

    Returns:
        dict of cookie_name -> cookie_value
    """
    console = Console()
    cookies_result = {}

    console.print(f"\n[bold cyan]Opening browser to:[/] {url}")
    console.print("[yellow]Please log in. The browser will auto-close once the auth cookie is detected.[/]")
    if not cookie_name:
        console.print("[yellow]Or close the browser manually when done logging in.[/]")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome",
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        page.goto(url, wait_until="domcontentloaded")

        start = time.time()
        detected = False

        while time.time() - start < timeout:
            try:
                all_cookies = context.cookies()
            except Exception:
                # Browser was closed by user
                break
            

            cookie_map = {c["name"]: c["value"] for c in all_cookies}

            if cookie_name:
                if cookie_name in cookie_map:
                    console.print(f"\n[bold green]✓ Cookie '{cookie_name}' captured![/]")
                    cookies_result = cookie_map
                    detected = True
                    break
            else:
                # Heuristic: detect common VPN auth cookies
                vpn_cookie_names = [
                    "DSID", "webvpn", "webvpnc", "SVPNCOOKIE",
                    "portal", "AUTH", "session", "token",
                ]
                for name in vpn_cookie_names:
                    if name in cookie_map:
                        console.print(f"\n[bold green]✓ Detected auth cookie: {name}[/]")
                        cookies_result = cookie_map
                        detected = True
                        break
                    if detected:
                        break

            if detected:
                break

            time.sleep(1)

        if not detected and not cookies_result:
            # Grab whatever cookies exist
            try:
                all_cookies = context.cookies()
                cookies_result = {c["name"]: c["value"] for c in all_cookies}
            except Exception:
                pass

        try:
            browser.close()
        except Exception:
            pass

    if not cookies_result:
        console.print("[bold red]✗ No cookies captured. Login may have failed or timed out.[/]")
    else:
        console.print(f"[green]Captured {len(cookies_result)} cookie(s).[/]")

    return cookies_result