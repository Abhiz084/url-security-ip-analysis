"""
Safe rendering utilities — iframe-based.
Streamlit cannot intercept → no Arrow / LargeUtf8 errors.
"""

import html as _html
import streamlit as st
import streamlit.components.v1 as components


def esc(value, max_len=150):
    """HTML-escape + truncate"""
    if value is None:
        return "—"
    s = _html.escape(str(value), quote=True)
    if max_len and len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def _iframe(html, height):
    """Render HTML in a sandboxed iframe. Bypasses ALL Streamlit processing."""
    components.html(html, height=height, scrolling=True)


def render_table(rows, columns, max_rows=50, empty_message="No data",
                 height_per_row=38, min_height=120):
    """
    Render a list of dicts as an HTML table.

    Uses st.components.v1.html() — the HTML goes inside an <iframe>,
    so Streamlit's Arrow serializer never sees it.
    """

    # ---------- Empty state ----------
    if not rows:
        html = f"""
        <!DOCTYPE html>
        <html><head><style>
            body {{ margin:0; padding:0; background:transparent;
                    font-family: 'Inter', system-ui, sans-serif; }}
        </style></head><body>
        <div style="text-align:center; padding:30px; color:#94a3b8;
                    background:rgba(30,41,59,0.3); border-radius:12px;
                    border:1px dashed rgba(96,165,250,0.2);">
            {esc(empty_message, max_len=None)}
        </div>
        </body></html>
        """
        _iframe(html, 100)
        return

    # ---------- Header cells ----------
    header_cells = "".join(
        f"""<th style="padding:12px; text-align:left; color:#60a5fa;
                     font-size:0.7rem; letter-spacing:1.5px;
                     text-transform:uppercase; font-weight:700;
                     white-space:nowrap;">{esc(c['label'], max_len=None)}</th>"""
        for c in columns
    )

    # ---------- Body rows ----------
    body_rows = ""
    for row in rows[:max_rows]:
        cells = ""
        for col in columns:
            raw = row.get(col['key']) if isinstance(row, dict) else None

            if 'render' in col:
                try:
                    content = col['render'](raw)
                except Exception:
                    content = esc(raw)
            else:
                content = esc(raw, max_len=col.get('max_len', 120))

            style = "padding:10px 12px; font-size:0.82rem;"
            if col.get('mono'):
                style += " font-family:'JetBrains Mono', monospace;"
            color = col.get('color', '#e2e8f0')
            style += f" color:{color};"
            if col.get('nowrap'):
                style += " white-space:nowrap;"

            cells += f'<td style="{style}">{content}</td>'

        body_rows += f"""
        <tr style="border-bottom:1px solid rgba(96,165,250,0.08);">{cells}</tr>
        """

    # ---------- Truncation note ----------
    truncated = ""
    if len(rows) > max_rows:
        truncated = f"""
        <div style="text-align:center; padding:10px; color:#64748b;
                    font-size:0.75rem; border-top:1px solid rgba(96,165,250,0.1);">
            Showing {max_rows} of {len(rows)} rows
        </div>
        """

    # ---------- Full HTML document ----------
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            * {{ box-sizing: border-box; }}
            body {{ margin:0; padding:0; background:transparent;
                    font-family: 'Inter', system-ui, -apple-system, sans-serif; }}
            table {{ width:100%; border-collapse:collapse; }}
            tr:hover {{ background: rgba(96,165,250,0.05); }}
        </style>
    </head>
    <body>
        <div style="background:rgba(30,41,59,0.4); border-radius:12px;
                    border:1px solid rgba(96,165,250,0.15); overflow:hidden;">
            <table>
                <thead>
                    <tr style="background:rgba(15,23,42,0.6);">{header_cells}</tr>
                </thead>
                <tbody>{body_rows}</tbody>
            </table>
            {truncated}
        </div>
    </body>
    </html>
    """

    # ---------- Auto-size height ----------
    rows_to_show = min(len(rows), max_rows)
    height = max(min_height, 60 + rows_to_show * height_per_row)
    _iframe(html, height)