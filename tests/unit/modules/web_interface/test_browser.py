"""Optional Chrome checks for the real web interface, with isolated API data."""

import json
import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Any
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlparse
from unittest.mock import Mock

import pytest

from modules.web_interface.server import RunDataReader
from slips_files.common.mac import classify_mac
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from tests.module_factory import ModuleFactory
from tests.unit.modules.web_interface.test_server import _network_scope_reader
from modules.web_interface.history import connect_history


def test_archive_selection_is_scoped_and_read_only_in_chrome() -> None:
    """Send archive queries and restore active controls when leaving an archive."""
    _factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    requests: list[str] = []
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Serve the real interface with an isolated archive catalogue.

        Parameters:
            route: Intercepted browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(
                path=str(assets / ("index.html" if path == "/" else path[1:]))
            )
        elif path == "/api/archives":
            route.fulfill(
                json={
                    "items": [
                        {
                            "id": "detections-2026-09-0001.sqlite",
                            "label": "2026-09-0001",
                        }
                    ]
                }
            )
        elif path == "/api/evidence":
            requests.append(route.request.url)
            route.fulfill(json={"items": [], "total": 0, "full_total": 0})
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.evaluate("() => loadArchiveCatalog()")
        page.locator('[data-tab="evidence"]').click()
        page.locator("#history-source").select_option(
            "detections-2026-09-0001.sqlite"
        )
        page.wait_for_function("() => !state.requests.has('evidence')")
        assert parse_qs(urlparse(requests[-1]).query)["archive"] == [
            "detections-2026-09-0001.sqlite"
        ]
        assert parse_qs(urlparse(requests[-1]).query)["range"] == ["all"]
        assert page.locator("#evidence-export").is_hidden()
        assert page.locator("#network-filter").is_disabled()
        assert page.evaluate("() => state.reviewAvailable") is False
        page.locator("#history-source").select_option("")
        assert page.locator("#evidence-export").is_visible()
        assert page.evaluate("() => state.reviewAvailable") is True
        assert errors == []
        browser.close()


@pytest.mark.parametrize("tab", ["evidence", "hosts"])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_polling_preserves_slow_table_requests_in_chrome(tab: str, theme: str) -> None:
    """Let slow tables finish while allowing filters to replace stale requests.

    Parameters:
        tab: Primary table whose request exceeds the polling interval.
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    pending: list[Any] = []
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Hold table responses and serve local assets with isolated API data.

        Parameters:
            route: Browser request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(
                path=str(assets / ("index.html" if path == "/" else path[1:]))
            )
        elif path == f"/api/{tab}":
            pending.append(route)
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.evaluate("theme => setTheme(theme)", theme)
        page.clock.install()
        page.locator(f'[data-tab="{tab}"]').click()
        page.wait_for_function("() => state.requests.has(state.activeTab)")
        page.wait_for_timeout(50)
        assert len(pending) == 1
        assert page.locator("#request-status").is_visible()
        assert page.locator("#request-status-label").inner_text() == "Loading…"
        assert page.locator("main").get_attribute("aria-busy") == "true"
        page.evaluate("() => schedulePoll()")
        page.clock.run_for(15000)
        assert len(pending) == 1
        assert page.evaluate("() => state.requests.has(state.activeTab)")

        page.locator(f"#{tab}-search").fill("scan")
        page.locator(f"#{tab}-search").press("Enter")
        page.wait_for_timeout(50)
        assert len(pending) == 2
        assert page.locator("#request-status-label").inner_text() == "Searching…"
        page.clock.run_for(300)
        assert len(pending) == 2
        pending[-1].fulfill(json={"items": [], "total": 0})
        page.locator("#request-status").wait_for(state="hidden")
        assert page.locator("main").get_attribute("aria-busy") == "false"
        page.locator(f"#{tab}-search").fill("other")
        page.locator(f"#{tab}-search").press("Enter")
        page.wait_for_timeout(50)
        assert page.locator("#request-status").is_visible()
        page.screenshot(path=f"output/request-status-{tab}-{theme}.png")
        pending[-1].fulfill(status=503, json={"error": "Search fixture failed"})
        page.locator("#request-status").wait_for(state="hidden")
        assert "Search fixture failed" in page.locator("#error-banner").inner_text()
        assert errors == []
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_host_network_summary_requires_matching_device_evidence_in_chrome(theme: str) -> None:
    """Keep guest DNS mentions and reused-IP devices out of device network history.

    Parameters:
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    ip = "192.168.1.185"
    mac = "2c:cf:67:5a:2e:bd"
    base = {"ip":ip,"first_seen":100,"last_seen":500,"user_name":"","user_note":"",
        "endpoint_first_seen":None,"endpoint_last_seen":None}
    profiles = [
        {**base,"network_id":"gateway:home","network_label":"Home-Wifi6","user_name":"homeassistant",
         "endpoint_first_seen":110,"endpoint_last_seen":190,
         "facts":[{"kind":"mac","value":mac,"first_seen":110,"last_seen":190,"observations":3},
                  {"kind":"mdns_hostname","value":"homeassistant.local","first_seen":110,"last_seen":190,"observations":2}]},
        {**base,"network_id":"gateway:guest","network_label":"Stratoguest",
         "facts":[{"kind":"dns_name","value":"homeassistant.local","first_seen":210,"last_seen":210,"observations":1}]},
        {**base,"network_id":"gateway:routed","network_label":"Routed network",
         "endpoint_first_seen":220,"endpoint_last_seen":230,"facts":[]},
        {**base,"network_id":"gateway:reused","network_label":"Reused private IP",
         "facts":[{"kind":"mac","value":"d8:58:d7:01:ff:e1","first_seen":300,"last_seen":400,"observations":2},
                  {"kind":"mdns_hostname","value":"router.local","first_seen":300,"last_seen":400,"observations":2}]},
    ]
    host = {"ip":ip,"mac":mac,"user_name":"homeassistant","scope":"local","live":True,
        "permanent_profiles":profiles,"alert_score":0,"alert_threshold":5,"load":{}}
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Serve shipped assets with isolated identity data.

        Parameters:
            route: Request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/","/app.js","/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/api/host-names":
            route.fulfill(json={"names":{}})
        else:
            route.fulfill(status=503,json={"error":"Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome",headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width":1600,"height":1100})
        page.on("pageerror",lambda error: errors.append(str(error)))
        page.route("**/*",route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof renderHostCards === 'function'")
        page.evaluate("""data => {
            clearTimeout(state.timer); clearTimeout(state.statusTimer); clearInterval(state.titleTimer);
            setTheme(data.theme); state.host=data.host; state.activeTab='hosts'; state.networkOnly=false;
            document.body.classList.add('hosts-active');
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active',panel.id==='hosts'));
            byId('hosts-list-view').hidden=true; byId('host-detail-view').hidden=false;
            rememberHostRecord(data.host); renderHostCards(data.host); updateHostViewportHeight(); clearError();
        }""",{"theme":theme,"host":host})
        summary = page.locator("#host-networks-seen")
        assert summary.locator(".host-clue-row").count() == 1
        assert "Home-Wifi6" in summary.inner_text()
        assert "MAC observed" in summary.inner_text()
        assert "Stratoguest" not in summary.inner_text()
        assert "Routed network" not in summary.inner_text()
        assert "Reused private IP" not in summary.inner_text()
        assert "3 unverified address histories" in summary.inner_text()
        assert summary.locator("strong").evaluate("node => getComputedStyle(node).whiteSpace") == "normal"
        assert "Verified device networks" in page.locator("#host-summary").inner_text()
        assert page.locator("#host-summary .summary-card").last.locator("strong").text_content() == "1 network"
        assert "router.local" not in page.locator("#host-mdns-names").inner_text()
        assert "homeassistant.local" in page.locator("#host-mdns-names").inner_text()
        assert "homeassistant" in page.locator("#host-title").inner_text()
        page.locator("#host-saved-history-label").click()
        archive = page.locator("#host-permanent-profiles")
        guest = archive.locator(".permanent-host-profile").filter(has_text="Stratoguest")
        assert guest.is_visible()
        assert "Device presence is unverified" in guest.inner_text()
        assert "homeassistant.local" in guest.inner_text()
        assert "Device attachment is unverified" in archive.inner_text()
        assert "A different device MAC" in archive.inner_text()
        markers = page.locator("#host-identity .mac-badge").all_text_contents()
        assert markers and set(markers) == {"U"}
        page.screenshot(path=f"output/host-network-presence-{theme}.png")
        assert errors == []
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_host_header_shows_full_device_addresses_in_chrome(theme: str) -> None:
    """Keep device addresses, identity and controls visible as aliases change.

    Parameters:
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    addresses = ["fe80::4c79:8745:56b3:21b5", "192.168.1.176",
        "fd9f:2ebd:5f8:0:47d:ecd3:3d81:ac52",
        *[f"2001:db8:1234:abcd:1111:2222:3333:{index}" for index in range(1, 9)]]
    host = {"ip": addresses[0], "device_ips": addresses, "all_ips": addresses,
        "hostname": "android_aehweocc.local", "scope": "local",
        "mac": "b8:7b:d4:97:ce:be", "mac_vendor": "Example device manufacturer",
        "alert_score": 0, "alert_threshold": 5, "peak_alert_score": 3.36,
        "alert_count": 0, "evidence_count": 0, "permanent_profiles": [],
        "capture_network": {"name": "Home-Wifi6"}, "seen_on_current_network": True}
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Serve host refreshes and assets without accessing a running capture.

        Parameters:
            route: Browser request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path.startswith("/api/hosts/"):
            if path.endswith("/flows"):
                route.fulfill(json={"items": [], "total": 0, "next_cursor": None})
            elif path.endswith("/traffic-summary"):
                route.fulfill(json={"timeline": [], "protocols": [], "peers": []})
            elif path.endswith("/score-history"):
                route.fulfill(json={"timeline": []})
            else:
                route.fulfill(json=host)
        elif path == "/api/host-names":
            route.fulfill(json={"names": {}})
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1334, "height": 1100})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof renderHostCards === 'function'")
        page.evaluate("""data => {
            clearTimeout(state.timer); clearTimeout(state.statusTimer); clearInterval(state.titleTimer);
            setTheme(data.theme); state.activeTab='hosts'; state.deviceView=true;
            state.networkOnly=true; state.networkFilterSupported=true;
            state.host=data.host; state.hostActivity='flows';
            document.body.classList.add('hosts-active');
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active',panel.id==='hosts'));
            byId('hosts-list-view').hidden=true; byId('host-detail-view').hidden=false;
            rememberHostRecord(data.host); renderHostCards(data.host); updateHostViewportHeight();
            clearError();
        }""", {"theme": theme, "host": host})
        heading = page.locator(".host-heading-copy")
        address_list = heading.locator(".device-addresses")
        assert address_list.text_content() == f"{len(addresses)} addresses · " + " · ".join(addresses)
        assert "android_aehweocc.local" in heading.inner_text()
        assert "Home-Wifi6" in heading.inner_text()
        assert "Example device manufacturer" in heading.inner_text()
        assert "b8:7b:d4:97:ce:be" in heading.inner_text()
        assert heading.locator(".mac-badge").text_content() == "U"
        assert "Current 0 / 5 · Peak 3.36 / 5" == page.locator("#host-score-pill").inner_text()
        for width in (900, 1334, 1920):
            page.set_viewport_size({"width": width, "height": 1100})
            geometry = page.evaluate("""addresses => {
                const header=byId('host-title').closest('.host-workspace-head');
                const box=header.getBoundingClientRect();
                const list=header.querySelector('.device-addresses');
                const style=getComputedStyle(list);
                const fits=rect => rect.left>=box.left-1 && rect.right<=box.right+1
                    && rect.top>=box.top-1 && rect.bottom<=box.bottom+1 && rect.right<=innerWidth;
                return {unclipped:style.whiteSpace==='normal' && style.overflow==='visible'
                        && list.scrollWidth<=list.clientWidth+1,
                    addresses:addresses.every(ip => {
                        const range=document.createRange(); const start=list.textContent.indexOf(ip);
                        range.setStart(list.firstChild,start); range.setEnd(list.firstChild,start+ip.length);
                        return [...range.getClientRects()].every(fits);
                    }),
                    identity:[...header.querySelectorAll('.host-label,.host-name,#host-subtitle,#host-score-pill')]
                        .every(node => fits(node.getBoundingClientRect())),
                    controls:[...header.querySelectorAll('button,select,input')]
                        .filter(node => !node.hidden).every(node => fits(node.getBoundingClientRect()))};
            }""", addresses)
            assert all(geometry.values()), (width, geometry)
            assert address_list.bounding_box()["width"] > 400
        page.set_viewport_size({"width": 1334, "height": 1100})
        page.screenshot(path=f"output/host-device-addresses-{theme}.png")
        rotated = addresses[:-1] + ["2001:db8:1234:abcd:aaaa:bbbb:cccc:dddd"]
        host.update(device_ips=rotated, all_ips=rotated)
        page.evaluate("refreshHostWorkspace()")
        assert address_list.text_content() == f"{len(rotated)} addresses · " + " · ".join(rotated)
        assert addresses[-1] not in address_list.text_content()
        page.evaluate("""() => {
            byId('host-range').value='custom'; byId('host-from').hidden=false; byId('host-to').hidden=false;
        }""")
        page.set_viewport_size({"width": 900, "height": 1100})
        assert page.locator(".host-workspace-head").evaluate("""header => {
            const box=header.getBoundingClientRect();
            return [...header.querySelectorAll('button,select,input')].filter(node => !node.hidden)
                .every(node => {const rect=node.getBoundingClientRect();
                    return rect.right<=innerWidth && rect.bottom<=box.bottom;});
        }""")
        page.evaluate("""() => {
            const compact=deviceIdentity(state.host); byId('hosts-list-view').append(compact);
            const style=getComputedStyle(compact.querySelector('.device-addresses'));
            window.compactAddressStyle={whiteSpace:style.whiteSpace,textOverflow:style.textOverflow};
            compact.remove(); state.deviceView=false; renderHostCards(state.host);
        }""")
        assert page.evaluate("window.compactAddressStyle") == {"whiteSpace": "nowrap", "textOverflow": "ellipsis"}
        assert heading.locator(".device-addresses").count() == 0
        assert addresses[0] in heading.inner_text()
        assert "android_aehweocc.local" in heading.inner_text()
        assert errors == []
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_host_flow_inspector_uses_shared_cards_in_chrome(tmp_path: Path, theme: str) -> None:
    """Inspect host flows with readable cards, related records, JSON and resizing.

    Parameters:
        tmp_path: Isolated retained flow database.
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    source = "fe80::4c79:8745:56b3:21b5"
    flows = [
        {"uid":"CaT8UtWwR1tbb8k7b", "starttime":100, "saddr":source, "daddr":"ff02::fb",
         "sport":5353, "dport":5353, "proto":"udp", "appproto":"dns", "dur":8.1939,
         "pkts":6,"bytes":1027,"state":"S0","smac":"b8:7b:d4:97:ce:be","dmac":"33:33:00:00:00:fb","history":"D","empty_field":""},
        {"uid":"http-flow", "starttime":90,"saddr":source,"daddr":"192.0.2.10","sport":50000,"dport":80,"proto":"tcp","appproto":"http","pkts":10,"bytes":2000},
        {"uid":"tls-flow", "starttime":80,"saddr":"2001:db8::10","daddr":source,"sport":443,"dport":50001,"proto":"tcp","appproto":"ssl","pkts":4,"bytes":500},
        {"uid":"plain-flow", "starttime":70,"saddr":source,"daddr":"192.0.2.11","sport":2000,"dport":2001,"proto":"udp","pkts":1,"bytes":5},
    ]
    rows = [{"uid":flow["uid"],"raw":flow,"event_time":flow["starttime"],"src_ip":flow["saddr"],"dst_ip":flow["daddr"],
        "src_port":flow["sport"],"dst_port":flow["dport"],"proto":flow["proto"],"app_proto":flow.get("appproto",""),
        "direction":"inbound" if flow["uid"] == "tls-flow" else "outbound", "peer":flow["saddr"] if flow["uid"] == "tls-flow" else flow["daddr"],
        "state":flow.get("state",""),"packets":flow["pkts"],"bytes":flow["bytes"],"duration":flow.get("dur",0),"label":"benign"} for flow in flows]
    rows[-1]["raw"] = {}
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript("CREATE TABLE flows(uid TEXT PRIMARY KEY,flow TEXT,label TEXT);"
            "CREATE TABLE altflows(uid TEXT,flow TEXT,flow_type TEXT);CREATE INDEX alt_uid ON altflows(uid);")
        connection.executemany("INSERT INTO flows VALUES (?,?,'benign')", [(flow["uid"],json.dumps(flow)) for flow in flows])
        connection.execute("UPDATE flows SET flow='{}' WHERE uid='plain-flow'")
        for index in range(23):
            connection.execute("INSERT INTO altflows VALUES (?,?,'dns')", (flows[0]["uid"],json.dumps({"uid":flows[0]["uid"],"query":f"printer-{index}.local","answers":["192.168.1.20"],"rcode_name":"NOERROR"})))
        connection.execute("INSERT INTO altflows VALUES ('http-flow',?,'http')", (json.dumps({"host":"example.test","uri":"/status","method":"GET","status_code":200}),))
        connection.execute("INSERT INTO altflows VALUES ('tls-flow',?,'ssl')", (json.dumps({"server_name":"secure.example.test","version":"TLSv13","validation_status":"ok"}),))
    requests: list[str] = []
    errors: list[str] = []
    held: list[Any] = []
    fail_http = False

    def route_request(route: Any) -> None:
        """Read selected flow details without touching a running capture.

        Parameters:
            route: Browser request intercepted before network access.
        """
        parsed = urlparse(route.request.url)
        if parsed.path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if parsed.path == "/" else parsed.path[1:])))
        elif parsed.path.startswith("/api/flows/"):
            uid = unquote(parsed.path[len("/api/flows/"):])
            requests.append(uid)
            if uid == "slow-flow":
                held.append(route)
            elif uid == "http-flow" and fail_http:
                route.fulfill(status=404, json={"error":"Temporarily unavailable"})
            else:
                route.fulfill(json=reader.flow_details(uid, parse_qs(parsed.query)))
        elif parsed.path == "/api/host-names":
            route.fulfill(json={"names":{source:{"name":"Android","source":"User name"}}})
        else:
            route.fulfill(status=503, json={"error":"Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width":1600,"height":1100})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof openHostFlow === 'function'")
        page.evaluate("""data => {
            setTheme(data.theme); state.activeTab='hosts'; state.host={ip:data.source};
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active',panel.id==='hosts'));
            byId('hosts-list-view').hidden=true; byId('host-detail-view').hidden=false;
            state.pages.hostFlows.items=data.rows; state.pages.hostFlows.total=data.rows.length;
            rememberHostName(data.source,'Android','User name');
            showHostActivity('flows'); renderHostFlows();
            Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value => {window.testCopied=value;}}});
        }""", {"theme":theme,"rows":rows,"source":source})
        assert requests == []
        table = page.locator("#host-flows-table")
        table.locator("tbody tr").first.click()
        page.wait_for_function("document.querySelector('.host-flow-protocol-status').textContent.includes('20 of 23')")
        page.evaluate("clearTimeout(state.timer); clearTimeout(state.statusTimer); clearInterval(state.titleTimer); clearError();")
        inspector = page.locator(".host-flow-inspector")
        assert inspector.locator(".flow-group").count() == 1
        assert source in inspector.locator(".flow-path").inner_text()
        assert inspector.locator(".flow-path .host-name").first.text_content() == "Android"
        assert "ff02::fb" in inspector.locator(".flow-path").inner_text()
        assert "Port 5353" in inspector.locator(".flow-path").inner_text()
        assert inspector.locator(".flow-metric").count() == 9
        assert "8.194 s" in inspector.inner_text()
        assert "1.0 KiB" in inspector.inner_text()
        assert inspector.locator(".json-details pre").count() == 0
        inspector.locator(".evidence-flow-actions button").click()
        assert page.evaluate("window.testCopied") == flows[0]["uid"]
        inspector.get_by_role("tab",name="Related DNS · 1",exact=True).click()
        assert "printer-0.local" in inspector.locator(".protocol-dns").inner_text()
        assert inspector.locator(".protocol-dns").count() == 1
        inspector.get_by_role("button",name="Load more protocol records",exact=True).click()
        page.wait_for_function("document.querySelector('.host-flow-protocol-status').textContent.includes('23 of 23')")
        assert inspector.get_by_role("tab",name="Related DNS · 1",exact=True).get_attribute("aria-selected") == "true"
        inspector.get_by_role("tab",name="Related DNS · 23",exact=True).click()
        assert "printer-22.local" in inspector.inner_text()
        inspector.get_by_role("tab",name="conn · flow",exact=True).click()
        assert inspector.locator(".mac-badge").all_text_contents() == ["U","M"]
        assert "Source" not in inspector.locator(".evidence-flow-table").inner_text()
        inspector.get_by_role("button",name="Show 1 empty fields",exact=True).click()
        assert inspector.get_by_role("button",name="Hide 1 empty fields",exact=True).is_visible()
        inspector.locator('[role="tabpanel"]:not([hidden]) summary').click()
        page.wait_for_function("document.querySelector('.host-flow-inspector .json-details pre') !== null")
        assert flows[0]["uid"] in inspector.locator(".json-details pre").inner_text()
        page.screenshot(path=f"output/host-flow-inspector-{theme}.png")
        handle = page.locator("#drawer-resize")
        handle.focus()
        before = page.locator("#drawer").bounding_box()["width"]
        handle.press("ArrowLeft")
        assert page.locator("#drawer").bounding_box()["width"] > before
        page.evaluate("setDrawerWidth(440)")
        assert inspector.locator(".flow-metrics").evaluate("node => getComputedStyle(node).gridTemplateColumns.split(' ').length") == 2
        assert inspector.evaluate("node => node.scrollWidth <= node.clientWidth"), inspector.evaluate("node => ({width:node.clientWidth,scroll:node.scrollWidth,overflow:[...node.querySelectorAll('*')].filter(child => child.getBoundingClientRect().right > node.getBoundingClientRect().right+1).map(child => [child.tagName,child.className,child.getBoundingClientRect().width])})")
        page.locator("#drawer-close").click()
        assert table.locator("tbody tr").count() == 4
        assert page.locator("#drawer-body").inner_text() == ""
        for index, kind, expected in ((1,"http","example.test"),(2,"ssl","secure.example.test")):
            table.locator("tbody tr").nth(index).click()
            page.wait_for_function("document.querySelector('.host-flow-protocol-status').textContent.includes('1 of 1')")
            inspector.get_by_role("tab",name=f"Related {kind.upper()} · 1",exact=True).click()
            assert expected in inspector.locator(f".protocol-{kind}").inner_text()
            page.locator("#drawer-close").click()
        table.locator("tbody tr").nth(3).click()
        page.wait_for_function("document.querySelector('.host-flow-protocol-status').textContent.includes('No related')")
        assert inspector.locator(".flow-metric").count() == 9
        assert "192.0.2.11" in inspector.locator(".flow-path").inner_text()
        page.locator("#drawer-close").click()
        fail_http = True
        table.locator("tbody tr").nth(1).click()
        page.get_by_role("button",name="Retry loading protocol records",exact=True).wait_for()
        assert inspector.locator(".flow-path").is_visible()
        fail_http = False
        inspector.get_by_role("button",name="Retry loading protocol records",exact=True).click()
        page.wait_for_function("document.querySelector('.host-flow-protocol-status').textContent.includes('1 of 1')")
        page.locator("#drawer-close").click()
        page.evaluate("row => {openHostFlow({...row,uid:'slow-flow'});}", rows[0])
        page.wait_for_function("state.requests.has('hostFlowDetail')")
        page.locator("#drawer-close").click()
        page.wait_for_function("!state.requests.has('hostFlowDetail')")
        for route in held:
            with suppress(playwright.Error):
                route.abort()
        assert page.locator("#drawer-body").inner_text() == ""
        assert errors == []
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_p2p_chart_matches_reliability_column_in_chrome(theme: str) -> None:
    """Identify the plotted metric and match its points and hover to the table.

    Parameters:
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    first_id = "QmFirstPeerWithAFullAuthenticatedIdentity123456789"
    second_id = "QmSecondPeerWithAFullAuthenticatedIdentity987654321"
    payload = {
        "enabled": True, "trust_range": "all",
        "counts": {"connected": 1, "known": 2},
        "peers": [
            {"peer_id": first_id, "ip": "192.168.1.170", "connected": True,
             "trust": 0.350, "reliability": 1, "first_seen": 50, "last_seen": 200},
            {"peer_id": second_id, "ip": "192.168.1.248", "connected": False,
             "trust": 0.34125, "reliability": 0.975, "first_seen": 75, "last_seen": 300},
        ],
        "calculated_trust_history": [
            {"peer_id": first_id, "timestamp": 100, "trust": -0.5},
            {"peer_id": first_id, "timestamp": 200, "trust": 0.350},
            {"peer_id": second_id, "timestamp": 100, "trust": 0.85},
            {"peer_id": second_id, "timestamp": 400, "trust": 0.34125},
        ],
        "trust_history": [
            {"peer_id": first_id, "timestamp": 100, "reliability": 0.9},
            {"peer_id": second_id, "timestamp": 100, "reliability": 0.94},
            {"peer_id": first_id, "timestamp": 200, "reliability": 1},
            {"peer_id": second_id, "timestamp": 300, "reliability": 0.975},
            {"peer_id": "missing-reliability", "timestamp": 350, "reliability": None},
            {"peer_id": "missing-time", "timestamp": None, "reliability": 0.5},
        ],
    }
    errors: list[str] = []
    ranges: list[str] = []

    def route_request(route: Any) -> None:
        """Serve a reliability history with distinct calculated trust values.

        Parameters:
            route: Browser request intercepted before network access.
        """
        parsed = urlparse(route.request.url)
        if parsed.path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if parsed.path == "/" else parsed.path[1:])))
        elif parsed.path == "/api/p2p":
            selected_range = parse_qs(parsed.query)["range"][0]
            ranges.append(selected_range)
            route.fulfill(json={**payload, "trust_range": selected_range})
        elif parsed.path == "/api/host-names":
            route.fulfill(json={"names": {}})
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1800, "height": 1100})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof loadP2P === 'function'")
        page.evaluate("""async theme => {
            setTheme(theme); state.activeTab='p2p';
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id==='p2p'));
            byId('p2p-range').value='all'; await loadP2P();
        }""", theme)
        assert page.locator(".p2p-chart-heading h3").inner_text() == "Peer reliability history"
        assert "table’s Reliability column" in page.locator(".p2p-chart-heading p").inner_text()
        assert page.locator("#p2p-range").get_attribute("aria-label") == "Peer reliability and trust history range"
        rows = page.locator("#p2p-peers-table tbody tr")
        assert rows.nth(0).locator("td").nth(3).inner_text() == "0.350"
        assert rows.nth(0).locator("td").nth(4).inner_text() == "1.000"
        assert rows.nth(1).locator("td").nth(3).inner_text() == "0.341"
        assert rows.nth(1).locator("td").nth(4).inner_text() == "0.975"
        assert page.locator("#p2p-trust-legend > span").count() == 2
        assert page.locator("#p2p-trust-legend code").first.inner_text() != first_id
        assert page.locator("#p2p-trust-legend > span").first.get_attribute("title") == first_id
        chart = page.locator("#p2p-trust-chart")
        assert chart.locator(".chart-y-label").all_text_contents() == ["0.800", "0.900", "1.000"]
        for index, reliability in enumerate((1, 0.975)):
            endpoint = chart.locator(f".peer-trust-line-{index}").evaluate(
                "path => path.getPointAtLength(path.getTotalLength()).y"
            )
            assert endpoint == pytest.approx(100 - (reliability - 0.8) / 0.2 * 88, abs=0.01)
        area = chart.locator(".chart-hit-area").bounding_box()
        for fraction, ip, expected in ((150 / 350, "192.168.1.170", "1.000"), (250 / 350, "192.168.1.248", "0.975")):
            page.mouse.move(area["x"] + area["width"] * fraction, area["y"] + area["height"] / 2)
            tooltip = chart.locator("..").locator(".chart-tooltip")
            assert tooltip.is_visible()
            assert ip in tooltip.inner_text()
            assert tooltip.inner_text().endswith(f": {expected}")
        page.evaluate("() => { window.savedReliabilityPath = document.querySelector('#p2p-trust-chart .chart-line'); }")
        page.evaluate("() => loadP2P()")
        assert page.evaluate("() => window.savedReliabilityPath === document.querySelector('#p2p-trust-chart .chart-line')")
        trust_chart = page.locator("#p2p-calculated-trust-chart")
        assert trust_chart.locator(".chart-y-label").all_text_contents() == ["0.000", "0.425", "0.850"]
        assert trust_chart.locator(".chart-line").count() == 2
        assert trust_chart.locator(".chart-time-label").all_text_contents() == chart.locator(".chart-time-label").all_text_contents()
        for svg in (chart, trust_chart):
            endpoint = svg.locator(".peer-trust-line-0").evaluate("path => path.getPointAtLength(path.getTotalLength()).x")
            bounds = svg.locator(".chart-hit-area").evaluate("node => ({left:Number(node.getAttribute('x')),width:Number(node.getAttribute('width'))})")
            assert endpoint == pytest.approx(bounds["left"] + 150 / 350 * bounds["width"], abs=0.01)
        for index, trust in enumerate((0.35, 0.34125)):
            endpoint = trust_chart.locator(f".peer-trust-line-{index}").evaluate("path => path.getPointAtLength(path.getTotalLength()).y")
            assert endpoint == pytest.approx(100 - trust / 0.85 * 88, abs=0.01)
            assert trust_chart.locator(f".peer-trust-line-{index}").get_attribute("clip-path")
        assert page.evaluate("() => state.p2p.calculated_trust_history[0].trust") == -0.5
        area = trust_chart.locator(".chart-hit-area").bounding_box()
        page.mouse.move(area["x"] + area["width"] * 0.999, area["y"] + area["height"] / 2)
        assert trust_chart.locator("..").locator(".chart-tooltip").inner_text().endswith(": 0.341")
        page.screenshot(path=f"output/p2p-reliability-{theme}.png")
        page.locator("#p2p-range").select_option("24h")
        page.wait_for_function("state.p2p.trust_range === '24h'")
        assert ranges[-1] == "24h"
        assert chart.locator(".chart-line").count() == 2
        assert trust_chart.locator(".chart-time-label").all_text_contents() == chart.locator(".chart-time-label").all_text_contents()
        page.evaluate("() => { window.savedTrustPath = document.querySelector('#p2p-calculated-trust-chart .chart-line'); }")
        payload["trust_history"].append({"peer_id": first_id, "timestamp": 500, "reliability": 1})
        page.evaluate("() => loadP2P()")
        assert not page.evaluate("() => window.savedTrustPath === document.querySelector('#p2p-calculated-trust-chart .chart-line')")
        assert trust_chart.locator(".chart-time-label").all_text_contents() == chart.locator(".chart-time-label").all_text_contents()
        for key in ("trust_history", "calculated_trust_history"):
            saved = payload[key]
            payload[key] = []
            page.evaluate("() => loadP2P()")
            assert trust_chart.locator(".chart-time-label").all_text_contents() == chart.locator(".chart-time-label").all_text_contents()
            assert len(chart.locator(".chart-time-label").all_text_contents()) == 3
            payload[key] = saved
        assert errors == []
        browser.close()


@pytest.mark.parametrize("width", [900, 1280, 1800])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_request_indicator_preserves_header_geometry_in_chrome(width: int, theme: str) -> None:
    """Keep loading, searching and idle header geometry identical.

    Parameters:
        width: Desktop or compact browser viewport width.
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")

    def route_request(route: Any) -> None:
        """Serve local assets and isolate the header from live API traffic.

        Parameters:
            route: Intercepted browser request.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": width, "height": 1100})
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("() => state.requests.size === 0")
        layouts = page.evaluate("""theme => {
            setTheme(theme);
            byId('run-name').textContent='sebas-en0';
            byId('run-device').textContent='This device · sebas-MacBook-Pro.local';
            for (const id of ['history-source-label','network-filter-label','device-view-label']) byId(id).hidden=false;
            state.requests.clear(); renderRequestActivity();
            const measure = () => ({
                scrollWidth:document.documentElement.scrollWidth,
                clientWidth:document.documentElement.clientWidth,
                brandScrollWidth:document.querySelector('.brand').scrollWidth,
                brandClientWidth:document.querySelector('.brand').clientWidth,
                checkboxWidths:[...document.querySelectorAll('.network-filter input')].map(input=>input.getBoundingClientRect().width),
                boxes:['.topbar','.brand','.topbar-actions','.tabs','main','#request-status'].map(selector => {
                    const rect=document.querySelector(selector).getBoundingClientRect();
                    return [rect.x,rect.y,rect.width,rect.height];
                }),
            });
            const layouts=[measure()];
            for (const label of ['Loading…','Searching…','Loading…']) {
                const controller=new AbortController(); controller.activityLabel=label;
                state.requests.set('layout-test',controller); renderRequestActivity();
                layouts.push(measure());
                state.requests.delete('layout-test'); renderRequestActivity();
                layouts.push(measure());
            }
            return layouts;
        }""", theme)
        for layout in layouts:
            assert layout["scrollWidth"] <= layout["clientWidth"] + 1
            assert layout["brandScrollWidth"] <= layout["brandClientWidth"] + 1
            assert all(width <= 24 for width in layout["checkboxWidths"])
            assert layout["scrollWidth"] == layouts[0]["scrollWidth"]
            for actual, expected in zip(layout["boxes"], layouts[0]["boxes"]):
                assert actual == pytest.approx(expected, abs=0.1)
        assert page.locator("#request-status").is_hidden()
        assert page.locator("main").get_attribute("aria-busy") == "false"
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_header_shows_all_ips_and_refreshes_outside_overview_in_chrome(theme: str) -> None:
    """All monitored IPs stay visible and current while another tab is selected.

    Parameters:
        theme: Browser color theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    ipv4 = ["192.168.1.247", "192.168.1.251"]
    ipv6 = ["fe80::4d6:6ff0:6f58:42b7", "fd9f:2ebd:5f8:0:47d:ecd3:3d81:ac52",
            *[f"2001:db8:1234:abcd:1111:2222:3333:{index}" for index in range(1, 8)]]
    heartbeat = {"interface":"en0", "connected":True, "name":"Home", "network_id":"home",
                 "host_ip":ipv4[0], "host_addresses":{"ipv4":ipv4, "ipv6":ipv6}}
    current_start = 100
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Supply current interface snapshots without reading a live run.

        Parameters:
            route: Browser request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/api/identity":
            route.fulfill(json={"review_actions":True, "network_filter_supported":True,
                "device_view_supported":True, "current_network_start":current_start, "current_network":heartbeat})
        elif path == "/api/host-names":
            route.fulfill(json={"names":{}})
        else:
            route.fulfill(status=503, json={"error":"Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width":1600, "height":1100})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof renderRunContext === 'function'")
        page.evaluate("""data => {
            setTheme(data.theme); state.activeTab='logs'; state.networkOnly=false;
            state.networkFilterSupported=true; state.deviceViewSupported=true; state.currentNetworkStart=100;
            state.headerNetwork=null;
            state.overview={run:{interface:'en0',input_type:'interface',output_dir:'output/run',state:'running',uptime_seconds:10},
                run_metadata:{'Slips version':'1.1.24'},computer_name:'Cherry.local',
                host_addresses:{ipv4:data.ipv4,ipv6:[...data.ipv6,data.ipv6[0]]},
                computer_addresses:{ipv4:[...data.ipv4,'198.51.100.20'],ipv6:data.ipv6},
                network_states:[{interface:'en0',connected:true,name:'Home',host_ip:data.ipv4[0]}],
                backend_status:{connected:true},counts:{alerts:0,evidence:0,hosts:0,module_errors:0}};
            renderRunContext(state.overview);
        }""", {"theme":theme,"ipv4":ipv4,"ipv6":ipv6})
        addresses = page.locator("#run-addresses")
        assert addresses.is_visible()
        assert addresses.locator("code").all_text_contents() == ipv4 + ipv6
        for width in (900, 1600):
            page.set_viewport_size({"width":width,"height":1100})
            for code in addresses.locator("code").all():
                assert code.is_visible()
                bounds = code.bounding_box()
                assert bounds["x"] >= 0
                assert bounds["x"] + bounds["width"] <= width
            assert addresses.bounding_box()["y"] + addresses.bounding_box()["height"] <= page.locator("header").bounding_box()["y"] + page.locator("header").bounding_box()["height"]
        page.screenshot(path=f"output/header-addresses-{theme}.png")
        rotated = ipv6[:-1] + ["2001:db8:1234:abcd:aaaa:bbbb:cccc:dddd"]
        heartbeat["host_addresses"] = {"ipv4":ipv4,"ipv6":rotated}
        page.evaluate("pollBackendStatus()")
        assert addresses.locator("code").all_text_contents() == ipv4 + rotated
        assert page.evaluate("ip => state.ownAddresses.has(ip)", ipv6[-1]) is False
        assert page.evaluate("ip => state.ownAddresses.has(ip)", rotated[-1]) is True
        assert page.evaluate("state.ownAddresses.has('198.51.100.20')") is True
        current_start = 200
        new_addresses = {"ipv4":["10.0.0.20"],"ipv6":["fe80::20","fd00::20","2001:db8:2::20"]}
        heartbeat.update(name="Office",network_id="office",host_ip="10.0.0.20",host_addresses=new_addresses)
        page.evaluate("pollBackendStatus()")
        assert "Office" in page.locator("#run-meta").inner_text()
        assert addresses.locator("code").all_text_contents() == new_addresses["ipv4"] + new_addresses["ipv6"]
        assert page.evaluate("state.activeTab") == "logs"
        assert page.evaluate("state.overview.host_addresses.ipv4") == ipv4
        heartbeat.update(connected=False,host_addresses={"ipv4":[],"ipv6":[]})
        page.evaluate("pollBackendStatus()")
        assert addresses.is_hidden()
        assert addresses.locator("code").count() == 0
        assert errors == []
        browser.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_compact_mac_markers_across_views_in_chrome(theme: str) -> None:
    """Keep names legible and MAC markers compact across structured views.

    Parameters:
        theme: Browser color theme, including the daylight theme.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Serve the shipped interface without contacting a running analysis.

        Parameters:
            route: Browser request intercepted before network access.
        """
        path = urlparse(route.request.url).path
        if path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if path == "/" else path[1:])))
        elif path == "/api/host-names":
            route.fulfill(json={"names": {}})
        else:
            route.fulfill(status=503, json={"error": "Isolated fixture"})

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof renderHostsPage === 'function'")
        page.evaluate("""theme => {
            setTheme(theme); state.activeTab='hosts'; state.networkOnly=false;
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id==='hosts'));
            state.pages.hosts.items=[
                {ip:'192.168.1.20', user_name:'Kitchen Pi', mac:'88:a2:9e:5e:93:42', mac_vendor:'Raspberry Pi (Trading) Ltd'},
                {ip:'192.168.1.21', user_name:'Work laptop', mac:'9c:b1:50:d4:c1:82', mac_vendor:'Intel Corporate'},
                {ip:'192.168.1.22', user_name:'Phone', mac:'9e:94:88:be:22:01'}
            ];
            state.pages.hosts.items.forEach(rememberHostRecord); renderHostsPage();
        }""", theme)
        assert "Kitchen Pi" in page.locator("#hosts-table tbody tr").first.inner_text()
        assert page.locator("#hosts-table .mac-badge").all_text_contents() == ["U", "U", "L"]
        assert "Locally administered" not in page.locator("#hosts-table").inner_text()
        local = page.locator("#hosts-table .mac-locally_administered")
        universal = page.locator("#hosts-table .mac-universally_administered").first
        local.hover()
        assert "Locally administered" in local.get_attribute("title")
        assert "Randomization cannot be determined" in local.get_attribute("aria-label")
        assert "Universally administered" in universal.get_attribute("title")
        assert local.evaluate("node => getComputedStyle(node).color") != universal.evaluate("node => getComputedStyle(node).color")
        for width in (1200, 1800):
            page.set_viewport_size({"width": width, "height": 1000})
            cell = page.locator("#hosts-table tbody tr").first.locator("td").nth(1)
            vendor = cell.locator("strong")
            address = cell.locator(".mac-identity")
            assert vendor.inner_text() == "Raspberry Pi (Trading) Ltd"
            assert vendor.bounding_box()["y"] < address.bounding_box()["y"]
            assert address.bounding_box()["height"] < 24
            assert cell.locator(".mac-badge").bounding_box()["width"] < 18
            assert address.bounding_box()["x"] + address.bounding_box()["width"] <= cell.bounding_box()["x"] + cell.bounding_box()["width"]
        page.screenshot(path=f"output/compact-mac-{theme}.png")
        page.evaluate("""() => {
            const profile={ip:'192.168.1.20', network_id:'home', network_label:'Home',
                facts:[{kind:'mac', value:'88:a2:9e:5e:93:42', last_seen:100}]};
            renderHostCards({ip:profile.ip, user_name:'Kitchen Pi', mac:'88:a2:9e:5e:93:42',
                mac_vendor:'Raspberry Pi (Trading) Ltd', permanent_profiles:[profile], annotation_profile:profile});
            renderNetworkStates([{interface:'en0', connected:true, gateway_mac:'d8:58:d7:00:67:11'}]);
            state.whitelists={rules:[{type:'MAC address',value:'A2:D7:7B:FA:6A:55'}],total:1}; renderWhitelists();
            state.arpPoisoning={hosts:[{ip:'192.168.1.20',mac:'88:a2:9e:5e:93:42'}],events:[],evidence:[],counts:{hosts:1}};
            renderArpPoisoning();
            byId('evidence-detail-content').replaceChildren(flowFieldList({
                client_mac:'A2:D7:7B:FA:6A:55',gateway_mac:'d8:58:d7:00:67:11'}));
            byId('evidence-detail-content').append(hostDescription({description:
                'MAC 9e:94:88:be:22:01 and 88:a2:9e:5e:93:42 at 192.168.1.20; fe80:aa:bb:cc:dd:ee:ff:00'}, 'test-mac-description'));
            const indicator=hostOrText('9e:94:88:be:22:01'); indicator.id='test-mac-indicator';
            byId('evidence-detail-content').append(indicator);
            renderLogs({items:[{event_time:100,module:'main',message:'Gateway MAC d8:58:d7:0:67:11'}],total:1});
        }""")
        for selector, expected in [("#host-subtitle", "U"), ("#host-identity", "U"),
            ("#host-permanent-profiles .host-profile-facts", "U"), (".host-name-scope", "U"),
            ("#network-states", "U"), ("#whitelists-table", "L"), ("#arp-poisoning-hosts-table", "U")]:
            assert page.locator(f"{selector} .mac-badge").first.text_content() == expected
        assert "MAC assignment" not in page.locator("#host-identity").inner_text()
        assert page.locator("#evidence-detail-content .evidence-flow-fields .mac-badge").all_text_contents() == ["L", "U"]
        assert page.locator(".test-mac-description .mac-badge").all_text_contents() == ["L", "U"]
        assert page.locator("#test-mac-indicator .mac-badge").text_content() == "L"
        assert page.locator("#logs-table .mac-badge").text_content() == "U"
        assert errors == []
        browser.close()


def test_host_findings_range_and_saved_filters_in_chrome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening a device preserves the inventory scope and explains hidden evidence.

    Parameters:
        tmp_path: Isolated retained evidence and history databases.
        monkeypatch: Fix the active capture clock.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    now = 2_000_000_000.0
    monkeypatch.setattr("modules.web_interface.server.time.time", lambda: now)
    reader = _network_scope_reader(tmp_path)
    reader._attach_current_host_scores = Mock(side_effect=lambda items: [
        item.update({"alert_score": 0, "alert_threshold": 5, "alert_score_mode": "ratl"}) for item in items
    ])
    ip = "192.168.1.249"
    with connect_history(reader.history_path) as connection:
        connection.execute("INSERT INTO host_snapshots VALUES (?, ?, ?)", (ip, now,
            json.dumps({"ip": ip, "scope": "local", "mac": "d8:3a:dd:bb:1d:6c"})))
        connection.execute("INSERT INTO flow_index(uid, flow_rowid, event_time, src_ip, dst_ip, bytes, packets) "
            "VALUES ('recent-host',1,?,?, '8.8.8.8',1,1)", (now-10, ip))
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.execute("INSERT INTO evidence(evidence_id,evidence_time,profile_ip,threat_level,"
            "evidence_type,source_module,description,accumulated_ratl) VALUES ('medium',?,?,'medium',"
            "'DEVICE_CHANGING_IP','flow_alerts','Device changed its IP',0.49)", (now-7200, ip))
    assets = Path("modules/web_interface")
    errors: list[str] = []

    def route_request(route: Any) -> None:
        """Run the real read APIs against isolated data and serve shipped assets.

        Parameters:
            route: Browser request intercepted before accessing the network.
        """
        url = urlparse(route.request.url)
        query = parse_qs(url.query)
        if url.path == "/api/hosts":
            route.fulfill(json=reader.hosts(query))
        elif url.path.startswith("/api/hosts/"):
            address, *resource = unquote(url.path).removeprefix("/api/hosts/").split("/")
            method = {"traffic-summary": reader.traffic_summary, "score-history": reader.score_history}.get(
                resource[0] if resource else "", reader.host)
            route.fulfill(json=method(address, query))
        elif url.path == "/api/evidence":
            route.fulfill(json=reader.evidence(query))
        elif url.path == "/api/alerts":
            route.fulfill(json=reader.alerts(query))
        elif url.path == "/api/host-names":
            route.fulfill(json={"names": {}})
        elif url.path == "/api/whitelists":
            route.fulfill(json={"rules": [], "counts": {}, "evidence_types": []})
        elif url.path.startswith("/api/"):
            route.fulfill(status=503, json={"error": "Isolated fixture"})
        elif url.path in {"/", "/app.js", "/style.css"}:
            route.fulfill(path=str(assets / ("index.html" if url.path == "/" else url.path[1:])))
        else:
            route.fulfill(status=404, body="")

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1800, "height": 1100})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.add_init_script(f"Date.now = () => {int(now * 1000)};")
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof loadHosts === 'function'")
        page.evaluate("""async ip => {
            state.activeTab='hosts'; state.deviceView=true; state.deviceViewSupported=true;
            state.networkOnly=false; state.hideExcluded=true;
            state.hostActivity='evidence'; state.hostActivityPreferred=true;
            state.hostActivityThreats.evidence='high_or_more'; state.hostActivityGroups.evidence='module';
            state.pages['host-evidence'].sort='type'; state.pages['host-evidence'].order='asc';
            byId('host-evidence-search').value='DEVICE_CHANGING_IP';
            byId('hosts-search').value=ip; byId('hosts-range').value='all'; byId('host-range').value='live';
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id==='hosts'));
            await loadHosts();
        }""", ip)
        row = page.locator("#hosts-table tbody tr").filter(has_text=ip)
        assert "0.49" in row.inner_text()
        assert "medium" in row.inner_text()
        row.click()
        page.wait_for_function("state.host?.ip === '192.168.1.249' && state.pages['host-evidence'].total === 0")
        assert page.locator("#host-range").input_value() == "all"
        assert page.evaluate("state.host.evidence_count") == 1
        assert "Peak 0.49" in page.locator("#host-score-pill").inner_text()
        notice = page.locator("#host-activity-filter-notice")
        assert "0 matching evidence · 1 in this range" in notice.inner_text()
        assert "High+" in notice.inner_text()
        notice.get_by_role("button", name="Clear activity filters", exact=True).click()
        page.wait_for_function("state.pages['host-evidence'].total === 1")
        assert "DEVICE_CHANGING_IP" in page.locator("#host-evidence-table tbody").inner_text()
        assert page.locator("#host-activity-group").input_value() == "module"
        assert page.evaluate("state.pages['host-evidence'].sort") == "type"
        assert page.locator("#host-evidence-search").input_value() == ""
        page.locator("#host-range").select_option("live")
        page.wait_for_function("state.host.evidence_count === 0 && state.pages['host-evidence'].total === 0")
        assert page.evaluate("state.host.peak_alert_score") is None
        page.locator("#host-range").select_option("all")
        page.wait_for_function("state.host.evidence_count === 1 && state.pages['host-evidence'].total === 1")
        page.locator('[data-host-activity="alerts"]').click()
        page.wait_for_function("document.querySelector('#host-alert-count').textContent.includes('0 alerts')")
        assert page.evaluate("state.host.alert_count") == 0
        assert errors == []
        browser.close()


def test_current_network_host_refresh_and_history_in_chrome() -> None:
    """Refreshing loaded pages removes stale hosts and clearly separates saved network history."""
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    assets = Path("modules/web_interface")
    rows = [
        {
            "ip": f"10.0.0.{index}",
            "scope": "local",
            "load": {"flows": 1},
            "last_seen": 1000,
            "evidence_count": 0,
            "alert_count": 0,
        }
        for index in range(1, 102)
    ]
    ghost = {"ip": "192.168.12.1", "scope": "local", "load": {"flows": 3}}
    requests: list[str] = []
    errors: list[str] = []
    pending_pages: list[tuple[Any, dict]] = []

    def route_request(route: Any) -> None:
        """Supply two fresh host pages and shipped application assets.

        Parameters:
            route: Browser request intercepted before accessing the network.
        """
        url = urlparse(route.request.url)
        if url.path == "/api/hosts":
            requests.append(route.request.url)
            query = parse_qs(url.query)
            items = rows[100:] if "cursor" in query else rows[:100]
            payload = {
                    "items": items,
                    "total": 101,
                    "page_size": len(items),
                    "next_cursor": None if "cursor" in query else "page-two",
                    "sort": "peak_score",
                    "order": "desc",
                    "range": "live",
                }
            if "cursor" in query:
                pending_pages.append((route, payload))
            else:
                route.fulfill(json=payload)
        elif url.path == "/api/host-names":
            route.fulfill(
                json={
                    "names": {
                        "192.168.1.1": {
                            "name": "Router",
                            "source": "Hostname",
                        },
                        "192.168.1.112": {
                            "name": "iPad-Storm",
                            "source": "User name",
                        },
                    }
                }
            )
        elif url.path == "/api/whitelists":
            route.fulfill(
                json={"rules": [], "counts": {}, "evidence_types": []}
            )
        elif url.path.startswith("/api/"):
            route.fulfill(status=503, json={"error": "Isolated fixture"})
        elif url.path in {"/", "/app.js", "/style.css"}:
            route.fulfill(
                path=str(
                    assets
                    / ("index.html" if url.path == "/" else url.path[1:])
                )
            )
        else:
            route.fulfill(status=404, body="")

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof loadHosts === 'function'")
        page.evaluate(
            """data => {
            state.activeTab='hosts'; state.networkOnly=true; state.networkFilterSupported=true;
            state.pages.hosts.items=[...data.rows.slice(0,100), data.ghost];
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'hosts'));
            window.hostRefresh=loadHosts();
        }""",
            {"rows": rows, "ghost": ghost},
        )
        page.wait_for_function("state.pages.hosts.items.length === 100 && state.requests.has('hostsRefreshMore')")
        assert page.locator("#hosts-table tbody tr").count() == 100
        assert "192.168.12.1" not in page.locator("#hosts-table").inner_text()
        page.wait_for_timeout(50)
        assert len(pending_pages) == 1
        pending_route, pending_payload = pending_pages.pop()
        pending_route.fulfill(json=pending_payload)
        page.evaluate("window.hostRefresh")
        assert len(requests) == 2
        assert all(
            parse_qs(urlparse(url).query)["network"] == ["current"]
            for url in requests
        )
        assert "192.168.12.1" not in page.locator("#hosts-table").inner_text()
        assert "10.0.0.101" in page.locator("#hosts-table").inner_text()
        assert page.locator("#hosts-table tbody tr").count() == 101
        assert page.locator("#hosts-badge").inner_text() == "101"
        page.evaluate("""() => {
            const table=document.querySelector('.hosts-list-table');
            table.style.height='250px'; table.style.flex='none'; table.scrollTop=300;
            window.hostScroll=table.scrollTop; window.hostRefresh=loadHosts();
        }""")
        page.wait_for_function("state.requests.has('hostsRefreshMore')")
        page.wait_for_timeout(50)
        assert page.evaluate("window.hostScroll") > 0
        assert page.locator("#hosts-table tbody tr").count() == 101
        assert page.locator(".hosts-list-table").evaluate("node => node.scrollTop") == page.evaluate("window.hostScroll")
        assert len(pending_pages) == 1
        pending_route, pending_payload = pending_pages.pop()
        pending_route.fulfill(json=pending_payload)
        page.evaluate("window.hostRefresh")
        assert page.locator(".hosts-list-table").evaluate("node => node.scrollTop") == page.evaluate("window.hostScroll")
        profiles = [
            {
                "ip": "192.168.1.20",
                "network_id": "run:old",
                "network_label": "Unidentified network · old run",
                "facts": [
                    {
                        "kind": "mdns_hostname",
                        "value": "past-device.local",
                        "last_seen": 100,
                        "first_seen": 100,
                    }
                ],
                "first_seen": 100,
                "last_seen": 100,
                "user_name": "",
                "user_note": "",
            },
            {
                "ip": "192.168.1.20",
                "network_id": "gateway:home",
                "network_label": "Home-Wifi6",
                "network_name": "Home-Wifi6",
                "facts": [
                    {
                        "kind": "mdns_hostname",
                        "value": "current-device.local",
                        "last_seen": 900,
                        "first_seen": 900,
                    }
                ],
                "first_seen": 900,
                "last_seen": 900,
                "user_name": "",
                "user_note": "",
            },
        ]
        profiles[1]["facts"].append(
            {
                "kind": "mdns_name",
                "value": "storm.local",
                "last_seen": 950,
                "first_seen": 950,
            }
        )
        host = {
            "ip": "192.168.1.20",
            "scope": "local",
            "live": True,
            "last_seen": 900,
            "load": {"flows": 1},
            "permanent_profiles": profiles,
            "current_network_profiles": [profiles[1]],
            "capture_network": {
                "name": "Home-Wifi6",
                "network_id": "gateway:home",
            },
            "seen_on_current_network": True,
        }
        page.evaluate(
            """host => {
            state.host=host; byId('hosts-list-view').hidden=true; byId('host-detail-view').hidden=false;
            renderHostCards(host);
        }""",
            host,
        )
        assert (
            "Observed on Home-Wifi6"
            in page.locator("#host-subtitle").inner_text()
        )
        assert (
            "Unidentified network"
            not in page.locator("#host-subtitle").inner_text()
        )
        assert "Home-Wifi6" in page.locator("#host-networks-seen").inner_text()
        assert (
            "Unidentified"
            not in page.locator("#host-networks-seen").inner_text()
        )
        assert (
            "past-device.local"
            not in page.locator("#host-mdns-names").inner_text()
        )
        page.locator("#host-saved-history-label").click()
        assert (
            "current-device.local"
            in page.locator("#host-mdns-names").inner_text()
        )
        assert (
            "storm.local" not in page.locator("#host-mdns-names").inner_text()
        )
        assert (
            "ownership unverified"
            in page.locator("#host-permanent-profiles").inner_text()
        )
        assert (
            "Unidentified network · old run"
            in page.locator("#host-permanent-profiles").inner_text()
        )
        host.update(
            {
                "seen_on_current_network": False,
                "current_network_profiles": [],
                "load": {"flows": 0},
            }
        )
        page.evaluate("host => {state.host=host; renderHostCards(host)}", host)
        assert (
            "No observed activity on Home-Wifi6"
            in page.locator("#host-subtitle").inner_text()
        )
        assert page.locator("#host-network-scope-note").is_visible()
        assert (
            page.locator("#host-networks-seen").inner_text()
            == "No observations on the current network."
        )
        page.wait_for_function(
            "!state.hostNamesLoading && !state.pendingHostNames.size"
        )
        page.evaluate("""async () => {
            state.hostNames.set('192.168.1.1', {name:'iPad-Storm', source:'User name'});
            state.pendingHostNames.add('192.168.1.1');
            state.pendingHostNames.add('192.168.1.112');
            await loadHostNames();
        }""")
        assert (
            page.evaluate("state.hostNames.get('192.168.1.1').name")
            == "Router"
        )
        assert (
            page.evaluate("state.hostNames.get('192.168.1.112').name")
            == "iPad-Storm"
        )
        page.evaluate("""() => {
            state.hostNames.set('192.168.1.1', {name:'iPad-Storm', source:'User name'});
            rememberHostRecord({ip:'192.168.1.1', user_name:'', hostname:'Router'});
        }""")
        assert (
            page.evaluate("state.hostNames.get('192.168.1.1').name")
            == "Router"
        )
        assert errors == []
        print(
            "Chrome network scope: all loaded pages revalidated; current capture, inactive host and full saved history passed"
        )
        browser.close()


@pytest.mark.parametrize("legacy", [False, True])
def test_large_grouped_record_loads_bounded_flows_in_chrome(tmp_path: Path, legacy: bool) -> None:
    """Opening a grouped device record renders one page and keeps protocol tabs usable.

    Parameters:
        tmp_path: Isolated flows database; no running Slips data is touched.
        legacy: Exercise a web server that still returns an unpaged flow list.
    """
    _module_factory = ModuleFactory()
    playwright = pytest.importorskip("playwright.sync_api")
    reader = RunDataReader.__new__(RunDataReader)
    reader.sqlite_path = tmp_path / "flows.sqlite"
    reader.redis = Mock()
    reader.redis.hgetall.return_value = {}
    reader.host_profiles_path = tmp_path / "hosts.sqlite"
    store = HostProfileStore(reader.host_profiles_path, "run", lambda _: {
        "gateway_mac": "aa:bb:cc:dd:ee:01", "local_network": "192.168.1.0/24",
    }, ["en0"])
    store.observe_flow(SimpleNamespace(interface="en0", starttime="100", type_="dhcp",
        saddr="192.168.1.20", daddr="192.168.1.1", host_name="laptop", smac="02:00:00:00:00:20"))
    reader._live_host = Mock(side_effect=lambda ip: {"ip": ip, "live": True})
    reader._attach_current_host_scores = Mock()
    reader._host_ips = Mock(return_value=["192.168.1.20"])
    reader._host_load = Mock(return_value={})
    reader._ti_for_ip = Mock(return_value={})
    reader.alerts = Mock(return_value={"items": [], "total": 0})
    reader._profile_evidence_count = Mock(return_value=0)
    with sqlite3.connect(reader.sqlite_path) as connection:
        connection.executescript(
            "CREATE TABLE flows(uid TEXT PRIMARY KEY, flow TEXT);"
            "CREATE TABLE altflows(uid TEXT, flow TEXT, flow_type TEXT);"
            "CREATE INDEX alt_uid ON altflows(uid);"
            "CREATE TABLE evidence_flows(evidence_id TEXT, uid TEXT, PRIMARY KEY(evidence_id,uid));"
        )
        for index in range(1051):
            uid = f"flow-{index:04}"
            connection.execute("INSERT INTO evidence_flows VALUES ('e', ?)", (uid,))
            connection.execute("INSERT INTO flows VALUES (?, ?)", (uid, json.dumps({
                "saddr": "192.168.1.20", "daddr": "8.8.8.8", "sport": 12345,
                "dport": 53, "proto": "udp", "starttime": 100, "bytes": 42,
            })))
            for protocol in range(8):
                connection.execute("INSERT INTO altflows VALUES (?, ?, 'dns')", (uid, json.dumps({
                    "query": f"query-{protocol}.example", "rcode_name": "NOERROR",
                    "answers": ["TXT " + "x" * 500], "uid": uid,
                })))
    record = {"id": "e", "profile_ip": "192.168.1.20", "evidence_type": "HIGH_ENTROPY_DNS_ANSWER",
              "description": "A DNS TXT answer with high entropy", "timestamp": 100,
              "threat_level": "low", "confidence": .8, "module": "flow_alerts", "flow_count": 1051}
    requests: list[dict[str, list[str]]] = []
    errors: list[str] = []
    whitelist_requests: list[dict[str, Any]] = []
    assets = Path("modules/web_interface")

    def route_request(route: Any) -> None:
        """Serve shipped assets and read-only flow pages inside the browser.

        Parameters:
            route: Playwright request route intercepted before network access.
        """
        url = urlparse(route.request.url)
        if url.path == "/api/host-annotation":
            payload = route.request.post_data_json
            route.fulfill(json=reader.save_host_annotation(**payload))
        elif url.path == "/api/whitelists" and route.request.method == "POST":
            payload = route.request.post_data_json
            whitelist_requests.append(payload)
            route.fulfill(json=payload)
        elif url.path == "/api/evidence/e/flows":
            query = parse_qs(url.query)
            requests.append(query)
            payload = reader.flows_for_evidence("e", {"limit": ["100"]} if legacy else query)
            if legacy:
                payload.pop("next_cursor", None)
            route.fulfill(json=payload)
        elif url.path == "/api/host-names":
            route.fulfill(json={"names": {}})
        elif url.path == "/api/whitelists":
            route.fulfill(json={"rules": [], "counts": {}, "evidence_types": []})
        elif url.path.startswith("/api/"):
            route.fulfill(status=503, json={"error": "Isolated browser fixture"})
        elif url.path in {"/", "/app.js", "/style.css"}:
            name = "index.html" if url.path == "/" else url.path[1:]
            route.fulfill(path=str(assets / name))
        else:
            route.fulfill(status=404, body="")

    with playwright.sync_playwright() as engine:
        try:
            browser = engine.chromium.launch(channel="chrome", headless=True)
        except playwright.Error as error:
            pytest.skip(f"Chrome is not available: {error}")
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/*", route_request)
        page.goto("http://slips.test/")
        page.wait_for_function("typeof openEvidence === 'function'")
        page.evaluate("""() => {
            localStorage.setItem(VIEW_PREFERENCES_KEY, JSON.stringify({paneWidths: {
                'evidence-workspace': {'--evidence-left-width':'5%', '--evidence-record-width':'5%'}
            }}));
            restoreViewPreferences();
        }""")
        assert page.evaluate("byId('evidence-workspace').style.getPropertyValue('--evidence-left-width')") == ""
        elapsed = page.evaluate("""async record => {
            state.activeTab = 'evidence'; state.deviceView = true;
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'evidence'));
            state.evidenceWorkspace.group = { id: 'mac:02:00:00:00:00:20', device_ips: ['192.168.1.20', 'fe80::20'] };
            state.evidenceWorkspace.records = [record];
            renderEvidenceGroup();
            const start = performance.now(); await openEvidence(record);
            return performance.now() - start;
        }""", record)
        assert elapsed < 3000
        mac_cases = [f"{value:02x}:d7:7b:fa:6a:55" for value in range(256)] + [
            "A2:D7:7B:FA:6A:55", "a2-d7-7b-fa-6a-55", "a2d7.7bfa.6a55", "a2d77bfa6a55",
            "d8:58:d7:0:67:11", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "bad", None, "",
        ]
        assert page.evaluate("values => values.map(classifyMac)", mac_cases) == [classify_mac(value) for value in mac_cases]
        workspace = page.locator("#evidence-workspace")
        group_pane = workspace.locator(".evidence-left")
        records_pane = page.locator("#evidence-right")
        workspace_width = workspace.bounding_box()["width"]
        assert .24 < group_pane.bounding_box()["width"] / workspace_width < .26
        assert .24 < records_pane.bounding_box()["width"] / workspace_width < .26
        assert page.locator("#evidence-detail").bounding_box()["width"] > .47 * workspace_width
        assert page.locator(".evidence-detail-columns").evaluate("element => getComputedStyle(element).gridTemplateColumns.split(' ').length") == 1
        assert page.locator(".evidence-detail-banner").evaluate("element => getComputedStyle(element).flexDirection") == "column"
        page.set_viewport_size({"width": 2400, "height": 1000})
        assert page.locator(".evidence-detail-columns").evaluate("element => getComputedStyle(element).gridTemplateColumns.split(' ').length") == 2
        page.set_viewport_size({"width": 1600, "height": 1000})
        assert records_pane.locator(".evidence-record-list").bounding_box()["height"] > 300
        for divider_id in ("#evidence-group-divider", "#evidence-detail-divider"):
            divider = page.locator(divider_id).bounding_box()
            page.mouse.move(divider["x"] + divider["width"] / 2, divider["y"] + 50)
            page.mouse.down()
            page.mouse.move(divider["x"] + divider["width"] / 2 + 50, divider["y"] + 50, steps=5)
            page.mouse.up()
        resized_widths = [group_pane.bounding_box()["width"], records_pane.bounding_box()["width"]]
        assert all(width > .27 * workspace_width for width in resized_widths)
        assert requests == [{"limit": ["20"]}]
        assert page.locator(".evidence-detail-flow-list .flow-group").count() == 20
        assert page.locator(".evidence-detail-flow-list .protocol-card").count() == 20
        assert page.locator(".evidence-detail-flow-list .json-details pre").count() == 0
        assert page.locator(".evidence-flow-status").inner_text() == "20 of 1.1k linked flows loaded"
        first = page.locator(".flow-group").first
        first.get_by_role("tab", name="Related DNS · 8", exact=True).click()
        assert "query-7.example" in first.inner_text()
        assert first.locator(".protocol-card").count() == 2
        first.get_by_role("tab", name="conn · flow", exact=True).click()
        first.locator("[role=tabpanel]:not([hidden]) summary").click()
        page.wait_for_function("document.querySelector('.flow-group .json-details pre') !== null")
        assert '"dport": 53' in first.locator(".json-details pre").inner_text()
        page.get_by_role("button", name="Load more triggering flows", exact=True).click()
        page.wait_for_function("document.querySelectorAll('.evidence-detail-flow-list .flow-group').length === 40")
        if legacy:
            assert len(requests) == 1
        else:
            assert requests[1]["cursor"] == ["flow-0019"]
        page.evaluate("closeEvidenceDetail()")
        assert page.locator("#evidence-detail-content .flow-group").count() == 0
        page.evaluate("record => openEvidence(record)", record)
        assert page.locator(".evidence-detail-flow-list .flow-group").count() == 20
        assert [group_pane.bounding_box()["width"], records_pane.bounding_box()["width"]] == resized_widths
        page.evaluate("saveViewPreferences()")
        page.reload()
        page.wait_for_function("typeof openEvidence === 'function'")
        page.evaluate("""record => {
            state.activeTab='evidence';
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id==='evidence'));
            state.evidenceWorkspace.records=[record];
            return openEvidence(record);
        }""", record)
        assert [group_pane.bounding_box()["width"], records_pane.bounding_box()["width"]] == resized_widths
        page.evaluate("""() => {
            const container = byId('evidence-detail-content');
            container.replaceChildren(flowCard({uid:'arp-test', network_flow:null, protocol_flows:[{
                flow_type:'arp', flow:{uid:'arp-test', saddr:'192.168.1.20', daddr:'192.168.1.212',
                    operation:'request', src_hw:'02:00:00:00:00:20', dst_hw:'00:00:00:00:00:00',
                    smac:'02:00:00:00:00:20', dmac:'ff:ff:ff:ff:ff:ff', interface:'en0'}
            }]}));
        }""")
        arp = page.locator(".protocol-arp")
        destination = arp.locator(".protocol-field").first
        assert destination.locator(":scope > small").inner_text() == "DESTINATION IP"
        assert "important" in destination.get_attribute("class")
        assert "192.168.1.212" in destination.inner_text()
        assert destination.locator("button").count() == 1
        assert "192.168.1.20" in arp.locator(".protocol-field").nth(1).inner_text()
        assert "DADDR" not in page.locator(".evidence-flow-fields").inner_text()
        assert arp.locator(".mac-locally_administered").count() == 2
        assert arp.locator(".mac-broadcast").inner_text() == "B"
        assert arp.locator(".mac-unspecified").inner_text() == "0"
        assert "Randomization cannot be determined" in arp.locator(".mac-locally_administered").first.get_attribute("title")
        assert errors == []
        page.evaluate("""host => {
            closeEvidenceDetail(); state.activeTab = 'hosts'; state.host = host;
            document.querySelectorAll('.panel').forEach(panel => panel.classList.toggle('active', panel.id === 'hosts'));
            byId('hosts-list-view').hidden = true; byId('host-detail-view').hidden = false;
            renderHostCards(host);
        }""", reader.host("192.168.1.20"))
        page.get_by_role("button", name="Mark or name this host", exact=True).click()
        form = page.locator("#host-annotation-entry .host-annotation-form")
        form.get_by_label("Review mark", exact=True).select_option("to_analyze")
        form.get_by_label("Labels (comma separated)", exact=True).fill("dns, lab")
        form.get_by_label("Custom name", exact=True).fill("My laptop")
        assert "Name and note follow MAC 02:00:00:00:00:20" in form.locator(".host-name-scope").text_content()
        form.get_by_label("Note", exact=True).fill("Inspect tomorrow")
        form.get_by_role("button", name="Save host review", exact=True).click()
        page.wait_for_function("state.host.user_status === 'to_analyze'")
        reopened = reader.host("192.168.1.20")
        assert reopened["user_labels"] == ["dns", "lab"]
        assert reopened["user_note"] == "Inspect tomorrow"
        assert reopened["user_name"] == "My laptop"
        restarted = HostProfileStore(reader.host_profiles_path, "new-run", lambda _: {
            "gateway_mac": "aa:bb:cc:dd:ee:01", "local_network": "192.168.1.0/24",
        }, ["en0"])
        restarted.observe_flow(SimpleNamespace(type_="conn", interface="en0", starttime=200,
            saddr="fe80::20", daddr="ff02::fb", smac="02:00:00:00:00:20"))
        assert HostProfileStore.read(reader.host_profiles_path, "fe80::20")[0]["user_name"] == "My laptop"
        page.evaluate("host => {state.host=host; renderHostCards(host)}", reopened)
        assert "To analyze" in page.locator("#host-identity").inner_text()
        assert "dns, lab" in page.locator("#host-identity").inner_text()
        assert "02:00:00:00:00:20" in page.locator("#host-identity").inner_text()
        identity_marker = page.locator("#host-identity > .detail-row > .mac-identity .mac-locally_administered")
        assert identity_marker.inner_text() == "L"
        assert "Randomization cannot be determined" in identity_marker.get_attribute("title")
        assert "MAC assignment" not in page.locator("#host-identity").inner_text()
        for device in (False, True):
            page.evaluate("""device => {
                state.deviceView=device;
                state.pages.hosts.items=[{ip:'192.168.1.20',mac:'A2:D7:7B:FA:6A:55',
                    device_ips:['192.168.1.20','fe80::20']}];
                renderHostsPage();
            }""", device)
            assert page.locator("#hosts-table .mac-locally_administered").inner_text() == "L"
        page.locator("#host-whitelist-action").click()
        assert page.locator("#drawer .whitelist-form input[list]").input_value() == "192.168.1.20"
        page.locator("#drawer .whitelist-form").get_by_role("button", name="Add rule", exact=True).click()
        page.wait_for_function("document.querySelector('#drawer .whitelist-feedback').textContent.includes('configured whitelist file')")
        assert whitelist_requests == [{"action": "add", "rule_type": "ip", "value": "192.168.1.20",
                                       "direction": "both", "ignore": "alerts", "evidence_type": ""}]
        print(f"Chrome grouped device record: {elapsed:.1f} ms; 20/1051 flows initially; protocol tabs, JSON, more, close/reopen passed")
        print("Chrome host editor: persisted review mark, labels, note, MAC and contextual whitelist passed")
        browser.close()
