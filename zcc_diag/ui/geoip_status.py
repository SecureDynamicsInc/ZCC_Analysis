"""MaxMind readiness: a landing-page status light and the shared setup panel.

Endpoint ownership is optional but it is the difference between reading a
packet capture as a list of bare addresses and reading it as attributable
destinations. Because the databases have to be fetched by hand — the
analyzer never calls a lookup service — the state has to be visible before
an engineer uploads a capture, not discovered afterwards inside a tab.

The uploader lives here rather than in ``endpoint_intelligence`` so the
landing page and the Problem endpoints tab drive the same code with
different widget keys.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Dict, Optional

import streamlit as st

from zcc_diag.endpoint_intel import (
    discover_databases,
    geoip_data_dir,
    save_database,
)

_MAXMIND_DOCS = "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/"


@dataclass(frozen=True)
class GeoipReadiness:
    """What local MaxMind data is present right now."""

    databases: Dict[str, str]

    @property
    def ready(self) -> bool:
        """ASN is the database that carries ownership; the rest are extras."""
        return "asn" in self.databases

    @property
    def has_geography(self) -> bool:
        return bool({"city", "country"} & set(self.databases))

    @property
    def summary(self) -> str:
        if not self.ready:
            return "No GeoLite2 ASN database on this workstation"
        names = ["ASN"]
        if "city" in self.databases:
            names.append("City")
        if "country" in self.databases:
            names.append("Country")
        return "GeoLite2 " + " + ".join(names) + " loaded locally"


def readiness() -> GeoipReadiness:
    return GeoipReadiness({kind: str(path) for kind, path in discover_databases().items()})


# --------------------------------------------------------------------------
# Shared setup panel
# --------------------------------------------------------------------------

def render_setup_panel(*, key_prefix: str, show_heading: bool = True) -> None:
    """Instructions plus the local ``.mmdb`` save control.

    ``key_prefix`` keeps the landing dialog and the Problem endpoints tab from
    colliding on widget keys when both render in one run.
    """
    state = readiness()
    if show_heading:
        st.markdown("#### Enable endpoint ownership")
    st.markdown(
        "Packet captures record addresses, not owners. A local **GeoLite2 ASN** "
        "database is what turns `104.129.198.10` into a named network, so a reset, "
        "retransmission, or unanswered SYN can be attributed to a Zscaler service "
        "edge, the customer's own server, or an unrelated provider."
    )
    st.markdown(
        f"1. Create a free MaxMind account and download **GeoLite2 ASN**. "
        f"[Open MaxMind download guidance ↗]({_MAXMIND_DOCS})\n"
        "2. **GeoLite2 City** is optional and adds country and city context.\n"
        "3. Choose the `.mmdb` file(s) below and save them on this workstation."
    )
    st.caption(
        "The databases stay local. Nothing is uploaded to SecureDynamics, Zscaler, "
        f"or MaxMind, and endpoint addresses are never sent to a lookup service. "
        f"Files are stored under `{geoip_data_dir()}` and are outside the repository. "
        "Wireshark's own MaxMind database folders are also detected."
    )

    uploads = st.file_uploader(
        "Choose GeoLite2 .mmdb files",
        type=["mmdb"],
        accept_multiple_files=True,
        key=f"{key_prefix}_maxmind_uploads",
    )
    if st.button(
        "Save databases on this workstation",
        disabled=not uploads,
        key=f"{key_prefix}_maxmind_save",
        type="primary",
    ):
        saved = []
        try:
            for upload in uploads:
                saved.append(save_database(upload.name, upload.getvalue()))
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the engineer
            st.error(f"The database could not be saved: {exc}")
        else:
            st.success(
                f"Saved {len(saved)} database(s) under {geoip_data_dir()}. "
                "Endpoint ownership will use them immediately."
            )
            st.rerun()

    if state.ready:
        st.divider()
        st.markdown("**Loaded now**")
        for kind, path in sorted(state.databases.items()):
            st.caption(f"{kind.upper()} · `{path}`")
    st.caption(
        "Keep downloaded databases current and remove superseded copies. This product "
        "includes GeoLite Data created by MaxMind, available from https://www.maxmind.com."
    )


def _open_setup_dialog() -> None:
    """Show the setup panel in its own view so the landing page stays short."""
    decorator = getattr(st, "dialog", None)
    if decorator is None:  # pragma: no cover - older Streamlit
        st.session_state["_geoip_inline_setup"] = True
        return

    @decorator("Endpoint ownership (MaxMind)", width="large")
    def _dialog() -> None:
        render_setup_panel(key_prefix="landing", show_heading=False)

    _dialog()


# --------------------------------------------------------------------------
# Landing card
# --------------------------------------------------------------------------

def render_landing_card() -> None:
    """A status light for endpoint ownership, sized to sit beside the uploader."""
    state = readiness()
    if state.ready:
        detail = (
            "Packet-capture endpoints resolve to ASN owner and provider class"
            + (", with country and city." if state.has_geography
               else ". Add GeoLite2 City for country and city.")
        )
        st.markdown(
            f"""
            <div class="la-start-card la-status-card">
              <b><span class="la-status-dot la-status-dot-ok"></span></b>
              <strong>Endpoint ownership · ready</strong>
              <span>{html.escape(state.summary)}. {html.escape(detail)}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander("Manage MaxMind databases"):
            render_setup_panel(key_prefix="landing_manage", show_heading=False)
        return

    st.markdown(
        """
        <div class="la-start-card la-status-card la-status-card-off">
          <b><span class="la-status-dot la-status-dot-off"></span></b>
          <strong>Endpoint ownership · not enabled</strong>
          <span>No local GeoLite2 ASN database. Packet captures will list bare IP
          addresses, so a reset, retransmission, or unanswered SYN cannot be
          attributed to a Zscaler service edge, the customer's own server, or an
          unrelated provider. Free to fix, one download.</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button(
        "Fix this · enable endpoint ownership",
        key="geoip_landing_cta",
        type="secondary",
        use_container_width=True,
    ):
        _open_setup_dialog()
    if st.session_state.get("_geoip_inline_setup"):
        with st.expander("Enable endpoint ownership", expanded=True):
            render_setup_panel(key_prefix="landing", show_heading=False)


def render_status_line(*, prefix: Optional[str] = None) -> None:
    """One-line readiness note for use inside a tab."""
    state = readiness()
    dot = "la-status-dot-ok" if state.ready else "la-status-dot-off"
    lead = f"{html.escape(prefix)} · " if prefix else ""
    st.markdown(
        f'<div class="la-status-line"><span class="la-status-dot {dot}"></span>'
        f'<span>{lead}{html.escape(state.summary)}</span></div>',
        unsafe_allow_html=True,
    )
