"""Build the single-file static demo served as the public URL.

Hugging Face charges for Docker Spaces but hosts Static Spaces free, and the
public demo only ever replays the recorded run in golden/ (live scans are
disabled on a public URL anyway). So this bakes that recording into the real
dashboard HTML: same page, same rendering code, no server.

A tiny shim answers the two GETs the dashboard makes (/api/config and
/api/demo) from inlined JSON, including the X-ShipCheck-Demo-Source header.
Everything else -- layout, scoring, the evidence timeline, the PASS gate --
is the dashboard's own code, so the static page cannot drift from the app.

    python scripts/build_static_demo.py            # -> deploy/static-demo/index.html
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from shipcheck.api.dashboard import DASHBOARD_HTML  # noqa: E402
from shipcheck.golden import GOLDEN_PATH  # noqa: E402

OUT = REPO / "deploy" / "static-demo" / "index.html"

SHIM = """<script>
// Static build: answer the dashboard's two API calls from the recorded run.
(function () {
  const DEMO = __DEMO_JSON__;
  const CONFIG = {public_demo: true};
  const json = (body, headers) => new Response(JSON.stringify(body), {
    status: 200, headers: Object.assign({"Content-Type": "application/json"}, headers || {}),
  });
  const real = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = String((input && input.url) || input || "");
    if (url.endsWith("/api/config")) return Promise.resolve(json(CONFIG));
    if (url.endsWith("/api/demo")) return Promise.resolve(json(DEMO, {"X-ShipCheck-Demo-Source": "golden"}));
    return real(input, init);
  };
})();
</script>
"""


def main() -> None:
    demo = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    # </script> inside the data would end the shim's own script tag early.
    payload = json.dumps(demo, separators=(",", ":")).replace("</", "<\\/")
    shim = SHIM.replace("__DEMO_JSON__", payload)

    marker = "<script>\nconst $ = s => document.querySelector(s);"
    if marker not in DASHBOARD_HTML:
        raise SystemExit("dashboard markup changed: update the shim insertion point")
    html = DASHBOARD_HTML.replace(marker, shim + marker, 1)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT} ({len(html) / 1024:.0f} KB, {demo['confirmed_count']} confirmed, "
          f"{demo['fixed_count']} fixed)")


if __name__ == "__main__":
    main()
