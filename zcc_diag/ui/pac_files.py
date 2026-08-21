"""The PAC file view: the customer's proxy auto-config, shown as-is.

A PAC decides per host whether traffic reaches a Zscaler service edge or goes
DIRECT, which makes it the first thing to read when a site is "not going
through the tunnel". The bundle only ever carries it inline in a log or as a
loose artefact, so this view recovers it and then gets out of the way: the
source is displayed unmodified and unabridged, with counts above it for
orientation and no verdict attached to any individual rule.
"""

from __future__ import annotations

import html
from typing import Any, Mapping, Sequence

import streamlit as st

from zcc_diag.endpoint_intel import lookup_ips
from zcc_diag.pac_extract import PacDocument, PacScan, describe


def _coverage_caption(scan: PacScan) -> str:
    parts = [
        f"{scan.files_scanned:,} of {scan.files_eligible:,} text files read",
        f"{scan.bytes_scanned / (1024 * 1024):.1f} MB scanned",
    ]
    if scan.hit_document_cap:
        parts.append("stopped at the distinct-PAC cap")
    if scan.hit_file_cap:
        parts.append("stopped at the file cap")
    if scan.hit_byte_cap:
        parts.append("stopped at the byte cap")
    return "Coverage · " + " · ".join(parts) + "."


def _document_label(document: PacDocument, position: int) -> str:
    tag = "PAC file" if document.standalone_file else "Inline PAC"
    repeats = f" ×{document.occurrences}" if document.occurrences > 1 else ""
    return f"{position}. {tag}{repeats} · {document.source_file}"


def _render_forwarding(info: Mapping[str, Any]) -> None:
    """Where this PAC sends traffic that is not bypassed.

    Zscaler's PAC server substitutes real Public Service Edge addresses for the
    ``${GATEWAY}`` family when it serves the file, so a PAC recovered from a
    client's logs normally names literal gateways where the authored template
    names variables. Literal addresses get the same local MaxMind treatment as
    any other endpoint, which is what confirms a gateway is Zscaler-owned and
    shows which data centre the client was pointed at.
    """
    targets = list(info.get("forwarding_targets") or ())
    if not targets:
        return

    st.markdown("#### Forwarding targets")
    if info.get("is_template"):
        st.info(
            "**Authored template.** The gateway placeholders below are still "
            "unsubstituted (`"
            + "`, `".join(str(name) for name in info["unresolved_variables"])
            + "`). Zscaler's PAC server replaces them with real Public Service "
            "Edge addresses when it serves the file, so a PAC recovered from a "
            "client's own logs will show addresses here instead."
        )
    else:
        st.caption(
            "Gateway addresses are substituted, so this is the forwarding list a "
            "client was actually served."
        )

    literal = [str(item["host"]) for item in targets
               if item["host"] and not item["variable"]]
    geo = lookup_ips(literal) if literal else {}

    rows = []
    for item in targets:
        host = str(item["host"] or "")
        record = geo.get(host)
        rows.append({
            "Order": item["order"],
            "Action": item["kind"],
            "Gateway": host or "— (direct, no proxy)",
            "Port": item["port"],
            "Form": "Variable" if item["variable"] else ("Address" if host else "—"),
            "Organization": record.organization if record else "",
            "ASN": record.asn if record else "",
            "Country": record.country if record else "",
            "City": record.city if record else "",
        })
    st.dataframe(
        rows,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Order": st.column_config.NumberColumn(width="small", format="%d"),
            "Gateway": st.column_config.TextColumn(width="medium"),
            "Port": st.column_config.NumberColumn(width="small", format="%d"),
            "Organization": st.column_config.TextColumn(width="large"),
        },
    )
    st.caption(
        "Order is the failover sequence inside the return statement: the client "
        "tries each entry in turn and falls through to DIRECT if one is present. "
        "Organization, ASN, Country, and City come only from local MaxMind data."
    )


def _render_document(document: PacDocument, *, pro_mode: bool) -> None:
    info = describe(document)

    st.markdown(
        f"""
        <div class="la-start-card">
          <b>PAC</b>
          <strong>{html.escape(document.origin)} · {html.escape(document.source_file)}</strong>
          <span>{document.line_count:,} lines · {document.byte_size:,} bytes ·
          fingerprint <code>{html.escape(document.fingerprint)}</code> ·
          seen {document.occurrences}× in {len(document.sources) or 1} file(s)</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    counts = st.columns(4)
    counts[0].metric(
        "DIRECT returns", info["direct_returns"],
        delta=(f"-{info['commented_direct_returns']} commented out"
               if info["commented_direct_returns"] else None),
        delta_color="off",
    )
    counts[1].metric("Proxy returns", info["proxy_returns"])
    counts[2].metric(
        "Host patterns", len(info["host_patterns"]),
        delta=(f"-{len(info['commented_host_patterns'])} commented out"
               if info["commented_host_patterns"] else None),
        delta_color="off",
    )
    counts[3].metric("Subnet tests", len(info["subnets"]))
    st.caption(
        "Counts cover **live rules only**. A PAC is a working document, so "
        "commented-out bypasses are excluded here and listed separately below — "
        "counting them as active would answer \"is this host bypassed?\" with a "
        "yes for a rule that is switched off. Counts describe what the file does; "
        "they are not a judgement about whether a bypass is correct for this tenant."
    )

    _render_forwarding(info)

    if document.truncated:
        st.warning(
            "The end of this PAC was not reached inside the recovery window. Treat the "
            "source below as a partial copy and confirm against the tenant's PAC "
            "configuration before concluding a rule is absent."
        )

    notes = []
    if document.preamble_stripped:
        notes.append(
            "ZCC wrote this PAC one log-prefixed line at a time; the timestamp preamble "
            "was removed so the source reads normally. Indentation is preserved."
        )
    if document.json_unescaped:
        notes.append(
            "This PAC was stored as an escaped configuration string; escape sequences "
            "were restored to real line breaks."
        )
    for note in notes:
        st.caption(note)

    if document.context:
        st.caption("Preceding log record")
        st.code(document.context, language=None, wrap_lines=True)

    st.markdown("#### PAC source")
    body = document.text
    if document.spacing_restored:
        as_found = st.toggle(
            "Show the extra blank lines exactly as the bundle held them",
            value=False,
            key=f"pac_as_found_{document.fingerprint}",
            help="Off restores the original spacing; on shows the recovered copy untouched.",
        )
        if as_found:
            body = document.as_found
        st.caption(
            f"A blank line followed almost every line of this copy, which is what a "
            f"writer does when each line carries both the file's own newline and the "
            f"writer's. {document.blank_lines_collapsed:,} blank line(s) were removed "
            f"— one from each run — to restore the original spacing. "
            + ("Showing the copy as found." if as_found
               else "Turn the toggle on to see it as found.")
        )
    st.caption(
        f"{len(body.splitlines()):,} lines, shown with the file's own indentation at "
        "4-space tabs. Long lines do not wrap, so the structure matches what an "
        "editor shows."
    )
    st.code(body, language="javascript", wrap_lines=False, line_numbers=True)
    st.caption(
        "This PAC is displayed only in the current run. Export is disabled so "
        "customer host names and gateway addresses are not copied into new files."
    )

    if not pro_mode:
        return

    if len(document.sources) > 1:
        with st.expander(f"Where this same PAC appeared ({len(document.sources)} files)"):
            for source in document.sources:
                st.caption(source)

    if info["proxy_targets"]:
        with st.expander(f"Proxy return statements ({len(info['proxy_targets'])} live)"):
            st.caption(
                "Each distinct live forwarding statement this PAC can return. The same "
                "value returned from several branches is listed once."
            )
            for target in info["proxy_targets"]:
                st.code(target, language=None, wrap_lines=True)

    if info["host_patterns"]:
        with st.expander(f"Host patterns matched by this PAC ({len(info['host_patterns'])} live)"):
            st.caption(
                "Every host given to a live shExpMatch, localHostOrDomainIs, or "
                "dnsDomainIs call, in file order. A pattern here is matched by the PAC; "
                "read the surrounding source above to see which branch it returns."
            )
            st.dataframe(
                [{"Host pattern": pattern} for pattern in info["host_patterns"]],
                hide_index=True,
                use_container_width=True,
                height=min(420, 40 + 35 * min(len(info["host_patterns"]), 11)),
            )

    commented_hosts = info["commented_host_patterns"]
    commented_returns = info["commented_proxy_targets"]
    if commented_hosts or commented_returns:
        with st.expander(
            f"Commented out — not in effect ({len(commented_hosts)} host patterns, "
            f"{len(commented_returns)} return statements)"
        ):
            st.caption(
                "These appear in the file but are inside `//` or `/* */` comments, so "
                "the PAC does not act on them. They are worth reading as deployment "
                "history — a bypass that was tried and withdrawn — but a host listed "
                "here is **not** currently bypassed."
            )
            if commented_returns:
                st.markdown("**Return statements**")
                for target in commented_returns:
                    st.code(target, language=None, wrap_lines=True)
            if commented_hosts:
                st.markdown("**Host patterns**")
                st.dataframe(
                    [{"Host pattern (inactive)": pattern} for pattern in commented_hosts],
                    hide_index=True,
                    use_container_width=True,
                    height=min(420, 40 + 35 * min(len(commented_hosts), 11)),
                )

    if info["subnets"]:
        with st.expander(f"Subnet tests ({len(info['subnets'])} live)"):
            for subnet in info["subnets"]:
                st.caption(subnet)

    if document.raw_excerpt:
        with st.expander("Surrounding raw log text (unprocessed)"):
            st.caption(
                "The window exactly as it sits in the log, before preamble stripping. "
                "Use it to confirm the recovered boundaries."
            )
            st.code(document.raw_excerpt, language=None, wrap_lines=True)


def render_pac_files(scan: Any, *, pro_mode: bool = True) -> None:
    st.markdown("## PAC files" if pro_mode else "## Proxy settings file")
    st.caption(
        "The proxy auto-config recovered from this bundle, shown exactly as it was "
        "found. A PAC decides which hosts bypass the tunnel and which are forwarded "
        "to a Zscaler service edge."
        if pro_mode else
        "The proxy settings file found in these logs. It lists which websites skip "
        "Zscaler protection and which are sent through it."
    )

    documents: Sequence[PacDocument] = getattr(scan, "documents", ())
    if not documents:
        st.info(
            "No PAC document was found in the material analyzed. This means no "
            "`FindProxyForURL` body was present in the files read — not that the "
            "tenant has no PAC. A PAC configured by URL is fetched at runtime and is "
            "only visible here when ZCC wrote its contents into a log that was "
            "included and read."
        )
        if pro_mode:
            st.caption(_coverage_caption(scan))
            if not scan.complete:
                st.caption(
                    "A scan cap was reached. Increase history depth or supply a bundle "
                    "with the tunnel and UPM logs to widen coverage."
                )
            for message in scan.unreadable[:3]:
                st.caption(f"Not readable: {message}")
        return

    if pro_mode:
        totals = st.columns(3)
        totals[0].metric("Distinct PACs", scan.found)
        totals[1].metric("Copies found", scan.total_occurrences)
        totals[2].metric("Files carrying a PAC", len({
            source for document in documents for source in (document.sources or (document.source_file,))
        }))

    if len(documents) == 1:
        _render_document(documents[0], pro_mode=pro_mode)
    else:
        st.caption(
            f"{len(documents)} PACs with different contents were recovered. Identical "
            "copies are already collapsed, so each entry below is a genuinely "
            "different file."
        )
        labels = [_document_label(document, position) for position, document in enumerate(documents, 1)]
        chosen = st.radio(
            "Which PAC",
            labels,
            key="pac_document_choice",
            horizontal=False,
        )
        _render_document(documents[labels.index(chosen)], pro_mode=pro_mode)

    if pro_mode:
        st.divider()
        st.caption(_coverage_caption(scan))
