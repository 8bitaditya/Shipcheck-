"""ShipCheck API + dashboard (FR-8).

A stateless FastAPI app that runs a scan (POST /scan) and serves a single-page
dashboard (GET /) showing the risk-ranked verdict, per-finding evidence, the
fix diff + re-verification gate, and the draft-PR link.
"""

from shipcheck.api.main import app

__all__ = ["app"]
