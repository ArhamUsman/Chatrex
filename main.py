"""NiceGUI security dashboard for the ChatreX chat client.

Importing this module only defines the web page. Run it as a script to start
NiceGUI; relay connections are created independently for each browser page.
"""

from __future__ import annotations

import argparse
import asyncio
import queue
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from nicegui import ui

from chatrex.client import ChatClient, ChatClientError, TrustError
from chatrex.protocol import (
    Mode,
    validate_room_code,
    validate_room_name,
    validate_username,
)
from chatrex.security import Identity, TrustStore


ROOT = Path(__file__).resolve().parent
USER_DATA = ROOT / "user_data"
CA_FILE = ROOT / "certs" / "ca.crt"
DEFAULT_RELAY_HOST = "10.0.3.10"
MAX_MESSAGE_BYTES = 65_536
MAX_DISPLAYED_MESSAGES = 500

MODE_OPTIONS = {
    Mode.E2E.value: "TLS 1.3 + X25519 end-to-end encryption",
    Mode.TLS.value: "TLS 1.3 transport encryption",
    Mode.PLAINTEXT.value: "Plaintext - INSECURE baseline",
}

MODE_DETAILS = {
    Mode.E2E: (
        "verified_user",
        "End-to-end protected",
        "TLS 1.3 protects transport. X25519 and NaCl Box encrypt separately for each verified peer. Compare fingerprints before sending.",
        "mode-e2e",
    ),
    Mode.TLS: (
        "lock",
        "Transport encrypted",
        "TLS 1.3 authenticates the relay and encrypts traffic on the network. The relay can still read room messages.",
        "mode-tls",
    ),
    Mode.PLAINTEXT: (
        "warning",
        "INSECURE plaintext baseline",
        "Messages and room credentials travel without transport encryption. Use only for controlled, isolated baseline testing.",
        "mode-plain",
    ),
}

DASHBOARD_CSS = r"""
:root {
    --cx-bg: #070b12;
    --cx-panel: rgba(15, 23, 36, 0.94);
    --cx-panel-soft: rgba(17, 27, 42, 0.76);
    --cx-line: rgba(148, 163, 184, 0.14);
    --cx-text: #e7edf5;
    --cx-muted: #8c9bad;
    --cx-cyan: #36d6df;
    --cx-green: #4ade9d;
    --cx-amber: #f3bc68;
    --cx-red: #fb7d8c;
}
body {
    background: var(--cx-bg);
    color: var(--cx-text);
    font-family: Inter, "IBM Plex Sans", "Segoe UI", sans-serif;
}
.nicegui-content {
    width: 100% !important;
    max-width: none !important;
    align-items: stretch !important;
    padding: 0 !important;
}
.cx-shell {
    align-self: stretch;
    width: 100%;
    max-width: none;
    min-width: 0;
    min-height: 100vh;
    min-height: 100dvh;
    background:
        radial-gradient(circle at 12% 0%, rgba(24, 133, 150, 0.13), transparent 34rem),
        radial-gradient(circle at 92% 12%, rgba(56, 89, 179, 0.10), transparent 32rem),
        linear-gradient(180deg, #080d15 0%, #070b12 100%);
    padding: 0 28px 36px;
}
.cx-topbar {
    width: 100%;
    max-width: 1380px;
    min-height: 86px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    border-bottom: 1px solid var(--cx-line);
}
.cx-brand {
    display: flex;
    align-items: center;
    gap: 13px;
}
.cx-brand-mark {
    width: 42px;
    height: 42px;
    display: grid;
    place-items: center;
    color: #071116;
    background: linear-gradient(145deg, #75eef2, #27bac8);
    border-radius: 12px;
    box-shadow: 0 8px 28px rgba(54, 214, 223, 0.17);
}
.cx-brand-name {
    font-size: 20px;
    line-height: 1.05;
    letter-spacing: 0.19em;
    font-weight: 800;
}
.cx-brand-subtitle, .cx-eyebrow {
    color: var(--cx-muted);
    font-size: 10px;
    line-height: 1.6;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    font-weight: 650;
}
.cx-capabilities {
    display: flex;
    align-items: center;
    gap: 9px;
}
.cx-capability, .cx-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    border: 1px solid var(--cx-line);
    border-radius: 999px;
    padding: 7px 11px;
    color: #afbdcc;
    background: rgba(15, 23, 36, 0.58);
    font-size: 11px;
    font-weight: 650;
    letter-spacing: 0.035em;
    white-space: nowrap;
}
.cx-workspace {
    width: 100%;
    max-width: none;
    margin: 34px auto 0;
}
.cx-lobby-grid {
    width: 100%;
    max-width: 1380px;
    margin: 0 auto;
    display: grid;
    grid-template-columns: minmax(0, 1.06fr) minmax(390px, 0.82fr);
    gap: clamp(36px, 6vw, 86px);
    align-items: center;
    min-height: calc(100vh - 170px);
    padding: 24px 18px 48px;
}
.cx-hero h1 {
    max-width: 680px;
    margin: 13px 0 20px;
    color: #f2f7fb;
    font-size: clamp(38px, 4.5vw, 64px);
    line-height: 1.06;
    letter-spacing: -0.045em;
    font-weight: 730;
}
.cx-hero h1 span { color: var(--cx-cyan); }
.cx-hero-copy {
    max-width: 620px;
    color: #9aaabd;
    font-size: 16px;
    line-height: 1.75;
}
.cx-feature-list {
    display: grid;
    gap: 12px;
    margin-top: 32px;
    max-width: 650px;
}
.cx-feature {
    display: flex;
    gap: 14px;
    align-items: flex-start;
    padding: 15px 16px;
    border: 1px solid var(--cx-line);
    border-radius: 13px;
    background: rgba(13, 21, 33, 0.54);
}
.cx-feature-icon {
    width: 34px;
    height: 34px;
    flex: 0 0 auto;
    display: grid;
    place-items: center;
    border-radius: 9px;
    color: var(--cx-cyan);
    background: rgba(54, 214, 223, 0.08);
}
.cx-feature-title { font-size: 13px; font-weight: 700; color: #dbe6ef; }
.cx-feature-copy { font-size: 12px; line-height: 1.55; color: var(--cx-muted); margin-top: 3px; }
.cx-access-card, .cx-chat-panel, .cx-side-panel {
    border: 1px solid var(--cx-line);
    background: var(--cx-panel);
    border-radius: 18px;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.27);
}
.cx-access-card { padding: 28px; }
.cx-card-title { font-size: 22px; font-weight: 720; letter-spacing: -0.02em; }
.cx-card-copy { color: var(--cx-muted); font-size: 12px; line-height: 1.6; }
.cx-section-label {
    color: #9dabbd;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.13em;
    text-transform: uppercase;
}
.cx-field .q-field__control {
    background: rgba(5, 11, 19, 0.52) !important;
    border-radius: 10px !important;
    color: var(--cx-text) !important;
}
.cx-field .q-field__label { color: #7f90a4 !important; }
.cx-field .q-field__native, .cx-field .q-field__input { color: #e5edf5 !important; }
.cx-field.q-field--focused .q-field__control { box-shadow: 0 0 0 1px rgba(54, 214, 223, 0.18); }
.cx-mode-notice {
    width: 100%;
    align-items: flex-start;
    flex-wrap: nowrap;
    gap: 11px;
    padding: 12px 13px;
    border: 1px solid;
    border-radius: 11px;
}
.cx-mode-notice.mode-e2e { color: var(--cx-green); border-color: rgba(74, 222, 157, 0.2); background: rgba(74, 222, 157, 0.055); }
.cx-mode-notice.mode-tls { color: var(--cx-cyan); border-color: rgba(54, 214, 223, 0.2); background: rgba(54, 214, 223, 0.055); }
.cx-mode-notice.mode-plain { color: var(--cx-red); border-color: rgba(251, 125, 140, 0.24); background: rgba(251, 125, 140, 0.065); }
.cx-mode-title { color: currentColor; font-size: 12px; font-weight: 750; }
.cx-mode-copy { color: #a2b0c0; font-size: 11px; line-height: 1.55; margin-top: 2px; }
.cx-primary-action .q-btn__content { font-weight: 700; letter-spacing: 0.015em; }
.cx-privacy-note { color: #748599; font-size: 10px; line-height: 1.55; text-align: center; }
.cx-chat-layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) clamp(300px, 22vw, 360px);
    gap: 18px;
    align-items: stretch;
    width: 100%;
    min-width: 0;
    min-height: 0;
}
.cx-chat-panel {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
}
.cx-chat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    padding: 19px 21px;
    border-bottom: 1px solid var(--cx-line);
    background: rgba(18, 28, 43, 0.62);
}
.cx-room-name { font-size: 20px; font-weight: 720; letter-spacing: -0.02em; overflow-wrap: anywhere; }
.cx-room-meta { color: var(--cx-muted); font-size: 11px; margin-top: 4px; }
.cx-code-box {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    padding: 7px 9px 7px 12px;
    border-radius: 9px;
    border: 1px solid rgba(54, 214, 223, 0.19);
    background: rgba(54, 214, 223, 0.06);
}
.cx-code-label { color: #7f93a8; font-size: 9px; letter-spacing: 0.13em; }
.cx-code { color: var(--cx-cyan); font-family: "JetBrains Mono", monospace; font-size: 15px; letter-spacing: 0.16em; font-weight: 750; }
.cx-status-pill.cx-pill-connected {
    color: #c8fbe2 !important;
    border-color: rgba(74, 222, 157, 0.32) !important;
    background: rgba(19, 78, 61, 0.72) !important;
}
.cx-status-pill.cx-pill-disconnected, .cx-status-pill.cx-pill-plain {
    color: #ffd1d7 !important;
    border-color: rgba(251, 125, 140, 0.32) !important;
    background: rgba(104, 38, 51, 0.68) !important;
}
.cx-status-pill.cx-pill-secure {
    color: #c5fbff !important;
    border-color: rgba(54, 214, 223, 0.30) !important;
    background: rgba(17, 75, 86, 0.68) !important;
}
.cx-trust-banner {
    margin: 15px 20px 0;
    padding: 12px 14px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    border: 1px solid rgba(243, 188, 104, 0.22);
    border-radius: 10px;
    color: var(--cx-amber);
    background: rgba(243, 188, 104, 0.055);
    font-size: 11px;
    line-height: 1.6;
}
.cx-trust-banner.ready { color: var(--cx-green); border-color: rgba(74, 222, 157, 0.18); background: rgba(74, 222, 157, 0.045); }
.cx-message-scroll {
    flex: 1 1 0;
    height: auto;
    min-height: 160px;
}
.cx-message-area { padding: 22px; min-height: 100%; }
.cx-empty-state { min-height: 330px; display: grid; place-content: center; justify-items: center; text-align: center; color: var(--cx-muted); }
.cx-message-row { display: flex; width: 100%; margin-bottom: 13px; }
.cx-message-row.own { justify-content: flex-end; }
.cx-message-wrap { max-width: min(78%, 680px); min-width: 0; }
.cx-message-meta { color: #8293a7; font-size: 10px; margin: 0 5px 5px; display: flex; gap: 8px; }
.cx-message-row.own .cx-message-meta { justify-content: flex-end; }
.cx-message-bubble {
    padding: 11px 14px;
    border: 1px solid #26364a;
    border-radius: 13px 13px 13px 3px;
    background: #172334;
    color: #dce6ef;
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}
.cx-message-row.own .cx-message-bubble {
    border-color: rgba(54, 214, 223, 0.24);
    border-radius: 13px 13px 3px 13px;
    background: linear-gradient(145deg, rgba(19, 100, 113, 0.66), rgba(15, 72, 88, 0.72));
    color: #ecfdff;
}
.cx-system-message { width: 100%; text-align: center; color: #7e90a5; font-size: 10px; line-height: 1.55; margin: 8px 0 14px; }
.cx-composer {
    flex: 0 0 auto;
    padding: 15px 19px 17px;
    border-top: 1px solid var(--cx-line);
    background: rgba(10, 17, 27, 0.72);
}
.cx-composer-note { color: #8293a7; font-size: 10px; line-height: 1.55; margin-bottom: 10px; }
.cx-composer-note.insecure { color: var(--cx-red); }
.cx-send-button { min-width: 44px; min-height: 40px; border-radius: 10px; }
.cx-sidebar {
    display: grid;
    gap: 16px;
    align-content: start;
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
    scrollbar-gutter: stable;
}
.cx-side-panel { padding: 18px; }
.cx-side-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 13px; }
.cx-side-title { font-size: 12px; font-weight: 750; letter-spacing: 0.04em; }
.cx-own-identity { padding: 11px 12px; border: 1px solid var(--cx-line); border-radius: 10px; background: rgba(8, 15, 24, 0.5); }
.cx-member-card { padding: 12px; margin-bottom: 9px; border: 1px solid var(--cx-line); border-radius: 11px; background: rgba(8, 15, 24, 0.46); }
.cx-member-name { font-size: 12px; font-weight: 700; overflow-wrap: anywhere; }
.cx-member-status { color: var(--cx-muted); font-size: 10px; margin-top: 2px; }
.cx-member-status.verified { color: var(--cx-green); }
.cx-member-status.unverified { color: var(--cx-amber); }
.cx-fingerprint {
    color: #b9c8d8;
    font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
    font-size: 10px;
    line-height: 1.75;
    overflow-wrap: anywhere;
    word-break: break-all;
    user-select: all;
}
.cx-verify-button { width: 100%; margin-top: 10px; }
.cx-verify-button .q-btn__content { white-space: normal; line-height: 1.4; font-size: 10px; padding: 4px 0; }
.cx-empty-members { color: var(--cx-muted); font-size: 11px; line-height: 1.6; padding: 12px 4px; }
.cx-relay-note { color: #718297; font-size: 10px; line-height: 1.6; }

/* Connected mode uses a fixed application viewport. Only messages and the
   member sidebar scroll; the composer remains visible without page scrolling. */
.cx-shell.chat-active {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    height: 100vh;
    height: 100dvh;
    min-height: 0;
    overflow: hidden;
    padding-bottom: 20px;
}
.cx-shell.chat-active .cx-topbar {
    flex: 0 0 76px;
    max-width: none;
    min-height: 76px;
}
.cx-workspace.chat-active {
    display: flex;
    flex: 1 1 0;
    min-height: 0;
    margin-top: 20px;
}
.cx-workspace.chat-active .cx-chat-layout {
    flex: 1 1 0;
    height: 100%;
}
.cx-workspace.chat-active .cx-chat-panel,
.cx-workspace.chat-active .cx-sidebar {
    height: 100%;
}
.cx-chat-header, .cx-trust-banner { flex: 0 0 auto; }

@media (max-width: 1020px) {
    .cx-lobby-grid { grid-template-columns: 1fr; min-height: auto; gap: 34px; padding-top: 36px; }
    .cx-hero h1 { max-width: 760px; }
    .cx-access-card { max-width: 650px; width: 100%; }
    .cx-chat-layout { grid-template-columns: 1fr; }
    .cx-sidebar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .cx-shell.chat-active {
        display: block;
        height: auto;
        min-height: 100vh;
        min-height: 100dvh;
        overflow: visible;
    }
    .cx-workspace.chat-active { display: block; }
    .cx-workspace.chat-active .cx-chat-layout { height: auto; }
    .cx-workspace.chat-active .cx-chat-panel {
        height: calc(100vh - 126px);
        height: calc(100dvh - 126px);
        min-height: 500px;
    }
    .cx-workspace.chat-active .cx-sidebar {
        height: auto;
        overflow: visible;
    }
}
@media (max-width: 680px) {
    .cx-shell { padding: 0 14px 22px; }
    .cx-topbar { min-height: 74px; }
    .cx-brand-subtitle, .cx-capabilities .cx-capability:first-child { display: none; }
    .cx-brand-name { font-size: 17px; }
    .cx-brand-mark { width: 36px; height: 36px; }
    .cx-capability { padding: 6px 8px; font-size: 9px; }
    .cx-workspace { margin-top: 18px; }
    .cx-lobby-grid { padding: 20px 0 28px; }
    .cx-hero h1 { font-size: 39px; }
    .cx-hero-copy { font-size: 14px; }
    .cx-access-card { padding: 20px 16px; border-radius: 15px; }
    .cx-chat-header { align-items: flex-start; flex-direction: column; padding: 16px; }
    .cx-message-area { padding: 16px 12px; }
    .cx-message-wrap { max-width: 90%; }
    .cx-composer { padding: 13px 12px; }
    .cx-sidebar { grid-template-columns: 1fr; }
    .cx-code-box { width: 100%; justify-content: space-between; }
}
"""


@dataclass
class DisplayMessage:
    """A safe, already-decoded message rendered by the UI thread."""

    sender: str
    text: str
    time: str
    own: bool = False
    system: bool = False


def _now() -> str:
    return datetime.now().strftime("%H:%M")


def _normalized_relay_host(value: str | None, fallback: str) -> str:
    """Validate the IPv4/DNS relay names supported by ChatClient's AF_INET socket."""

    host = (value or "").strip() or fallback
    if not host or len(host) > 253 or host != host.strip():
        raise ValueError("invalid relay host")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("invalid relay host")
    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid relay host")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("invalid relay host")
    return host


def _close_client(client: ChatClient) -> None:
    """Best-effort shutdown without emitting secrets or raising into the UI."""

    try:
        client.close()
    except Exception:
        # A socket may already have been closed by the listener thread.
        pass
    finally:
        client.password = ""


class DashboardController:
    """Own exactly one ChatClient and all UI state for one NiceGUI page."""

    def __init__(self, default_relay_host: str):
        self.default_relay_host = default_relay_host
        self.client: ChatClient | None = None
        self.status = "idle"
        self.form_mode = Mode.E2E
        self.messages: list[DisplayMessage] = []
        self.peer_names: set[str] = set()
        self.events: queue.Queue[tuple[int, dict[str, Any]]] = queue.Queue()
        self.generation = 0
        self.busy = False
        self.send_in_flight = False

        self.action_buttons: list[Any] = []
        self.busy_row: Any = None
        self.busy_label: Any = None
        self.mode_input: Any = None
        self.username_input: Any = None
        self.server_input: Any = None
        self.room_name_input: Any = None
        self.room_code_input: Any = None
        self.create_password_input: Any = None
        self.join_password_input: Any = None
        self.message_input: Any = None
        self.send_button: Any = None
        self.shell_element: Any = None
        self.workspace_element: Any = None

    def build(self) -> None:
        ui.colors(primary="#36d6df", secondary="#172334", positive="#4ade9d")
        ui.dark_mode().enable()
        ui.add_css(DASHBOARD_CSS)

        with ui.element("div").classes("cx-shell") as self.shell_element:
            self._build_header()
            with ui.element("main").classes("cx-workspace") as self.workspace_element:
                self.render_workspace()

        # Listener callbacks only enqueue. Every UI mutation happens here or in
        # a NiceGUI event handler on the page's UI thread.
        ui.timer(0.15, self._poll_events)
        ui.context.client.on_disconnect(self._page_disconnected)

    def _build_header(self) -> None:
        with ui.element("header").classes("cx-topbar"):
            with ui.element("div").classes("cx-brand"):
                with ui.element("div").classes("cx-brand-mark"):
                    ui.icon("shield", size="24px")
                with ui.column().classes("gap-0"):
                    ui.label("CHATREX").classes("cx-brand-name")
                    ui.label("Security operations console").classes("cx-brand-subtitle")
            with ui.element("div").classes("cx-capabilities"):
                with ui.element("div").classes("cx-capability"):
                    ui.icon("lock", size="15px")
                    ui.label("TLS 1.3")
                with ui.element("div").classes("cx-capability"):
                    ui.icon("fingerprint", size="15px")
                    ui.label("X25519 E2E")

    @ui.refreshable
    def render_workspace(self) -> None:
        if self.status in {"connected", "disconnected"} and self.client is not None:
            self._render_chat()
        else:
            self._render_lobby()

    def _render_lobby(self) -> None:
        self.shell_element.classes(remove="chat-active")
        self.workspace_element.classes(remove="chat-active")
        self.message_input = None
        self.send_button = None
        self.action_buttons = []
        self.busy_row = None
        self.busy_label = None

        with ui.element("div").classes("cx-lobby-grid"):
            with ui.element("section").classes("cx-hero"):
                ui.label("Multi-mode secure communication").classes("cx-eyebrow")
                with ui.element("h1"):
                    ui.label("Private conversations.")
                    ui.label("Explicit trust.").classes("block text-[#36d6df]")
                ui.label(
                    "A focused messaging console for routed labs and controlled "
                    "security comparisons. Choose the protection you need, then "
                    "verify exactly who receives your end-to-end encrypted messages."
                ).classes("cx-hero-copy")

                with ui.element("div").classes("cx-feature-list"):
                    self._feature(
                        "lock",
                        "TLS 1.3 transport",
                        "Certificate-verified TLS for secure transport sessions, using the project CA at certs/ca.crt.",
                    )
                    self._feature(
                        "fingerprint",
                        "X25519 end-to-end encryption",
                        "Persistent per-user identity, per-recipient encryption, and explicit out-of-band peer verification.",
                    )
                    self._feature(
                        "science",
                        "Plaintext baseline - INSECURE",
                        "Unencrypted mode is provided only for isolated measurements and protocol comparisons.",
                    )
                    ui.label(
                        f"Default routed-lab relay: {self.default_relay_host}. "
                        "This dashboard never starts a relay automatically."
                    ).classes("cx-relay-note mt-2")

            with ui.element("section").classes("cx-access-card"):
                ui.label("Room access").classes("cx-eyebrow")
                ui.label("Enter a ChatreX room").classes("cx-card-title mt-1")
                ui.label(
                    "Create a room or join with its six-digit code. When joining, "
                    "select the same security mode chosen by the room creator."
                ).classes("cx-card-copy mt-1 mb-5")

                self.username_input = ui.input(
                    "Username", placeholder="Letters, digits, underscore, hyphen"
                ).classes("cx-field w-full mb-3").props(
                    "dark outlined dense maxlength=24 autocomplete=off spellcheck=false"
                )
                self.server_input = ui.input(
                    "Relay server (optional)",
                    value=self.default_relay_host,
                    placeholder=self.default_relay_host,
                ).classes("cx-field w-full mb-1").props(
                    "dark outlined dense maxlength=253 autocomplete=off spellcheck=false"
                )
                ui.label(
                    "Plaintext uses port 8080; TLS and E2E use port 8443."
                ).classes("cx-card-copy mb-4")

                self.mode_input = ui.select(
                    MODE_OPTIONS,
                    value=self.form_mode.value,
                    label="Security mode",
                    on_change=self._mode_changed,
                ).classes("cx-field w-full mb-3").props("dark outlined dense options-dark")
                self.render_mode_notice()

                with ui.tabs().classes("w-full mt-5 text-cyan-300") as tabs:
                    create_tab = ui.tab("Create room", icon="add")
                    join_tab = ui.tab("Join room", icon="login")

                with ui.tab_panels(tabs, value=create_tab).classes("w-full bg-transparent p-0"):
                    with ui.tab_panel(create_tab).classes("p-0 pt-4"):
                        self.room_name_input = ui.input(
                            "Room name", placeholder="e.g. routed-security-lab"
                        ).classes("cx-field w-full mb-3").props(
                            "dark outlined dense maxlength=32 autocomplete=off"
                        )
                        self.create_password_input = ui.input(
                            "Room password",
                            placeholder="Required; never saved",
                            password=True,
                            password_toggle_button=True,
                        ).classes("cx-field w-full mb-4").props(
                            "dark outlined dense maxlength=256 autocomplete=off"
                        )
                        create_button = ui.button(
                            "Create room",
                            icon="arrow_forward",
                            on_click=lambda: self._connect("create"),
                        ).classes("cx-primary-action w-full").props(
                            "color=primary text-color=dark unelevated no-caps"
                        )
                        self.action_buttons.append(create_button)

                    with ui.tab_panel(join_tab).classes("p-0 pt-4"):
                        self.room_code_input = ui.input(
                            "Six-digit room code", placeholder="e.g. 048215"
                        ).classes("cx-field w-full mb-3").props(
                            "dark outlined dense maxlength=6 inputmode=numeric autocomplete=off"
                        )
                        self.join_password_input = ui.input(
                            "Room password",
                            placeholder="Required; never saved",
                            password=True,
                            password_toggle_button=True,
                        ).classes("cx-field w-full mb-4").props(
                            "dark outlined dense maxlength=256 autocomplete=off"
                        )
                        join_button = ui.button(
                            "Join room",
                            icon="arrow_forward",
                            on_click=lambda: self._connect("join"),
                        ).classes("cx-primary-action w-full").props(
                            "color=primary text-color=dark unelevated no-caps"
                        )
                        self.action_buttons.append(join_button)

                ui.label(
                    "Room passwords are held only for registration and are not written to disk."
                ).classes("cx-privacy-note mt-4")
                self.busy_row = ui.row().classes("w-full items-center justify-center gap-2 mt-3")
                with self.busy_row:
                    ui.spinner("dots", size="20px", color="cyan")
                    self.busy_label = ui.label("Connecting safely...").classes("text-xs text-cyan-200")
                self.busy_row.set_visibility(False)

    @staticmethod
    def _feature(icon: str, title: str, copy: str) -> None:
        with ui.element("div").classes("cx-feature"):
            with ui.element("div").classes("cx-feature-icon"):
                ui.icon(icon, size="19px")
            with ui.column().classes("gap-0"):
                ui.label(title).classes("cx-feature-title")
                ui.label(copy).classes("cx-feature-copy")

    @ui.refreshable
    def render_mode_notice(self) -> None:
        try:
            mode = Mode(self.mode_input.value)
        except (ValueError, TypeError):
            mode = self.form_mode
        icon, title, copy, css_class = MODE_DETAILS[mode]
        with ui.row().classes(f"cx-mode-notice {css_class}"):
            ui.icon(icon, size="20px").classes("mt-0.5")
            with ui.column().classes("gap-0 flex-1"):
                ui.label(title).classes("cx-mode-title")
                ui.label(copy).classes("cx-mode-copy")

    def _mode_changed(self) -> None:
        try:
            self.form_mode = Mode(self.mode_input.value)
        except (ValueError, TypeError):
            self.form_mode = Mode.E2E
        self.render_mode_notice.refresh()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        for button in self.action_buttons:
            if busy:
                button.disable()
            else:
                button.enable()
        if self.busy_row is not None:
            self.busy_row.set_visibility(busy)

    async def _connect(self, action: str) -> None:
        if self.busy or self.status not in {"idle", "disconnected"}:
            return

        username = (self.username_input.value or "").strip()
        if not validate_username(username):
            ui.notify(
                "Username must be 1-24 ASCII letters, digits, underscores, or hyphens.",
                type="warning",
            )
            return

        try:
            relay_host = _normalized_relay_host(
                self.server_input.value, self.default_relay_host
            )
        except ValueError:
            ui.notify(
                "Enter a valid IPv4 address or DNS hostname for the relay.",
                type="warning",
            )
            return

        try:
            mode = Mode(self.mode_input.value)
        except (ValueError, TypeError):
            ui.notify("Select a valid security mode.", type="warning")
            return

        room_name: str | None = None
        room_code: str | None = None
        if action == "create":
            room_name = (self.room_name_input.value or "").strip()
            password = self.create_password_input.value or ""
            if not validate_room_name(room_name):
                ui.notify(
                    "Room name must be 1-32 printable characters.", type="warning"
                )
                return
        else:
            room_code = (self.room_code_input.value or "").strip()
            password = self.join_password_input.value or ""
            if not validate_room_code(room_code):
                ui.notify("Room code must contain exactly six digits.", type="warning")
                return

        if not password or len(password) > 256:
            ui.notify("Room password must contain 1-256 characters.", type="warning")
            return
        if mode is not Mode.PLAINTEXT and not CA_FILE.is_file():
            ui.notify(
                "Secure connection unavailable: certs/ca.crt is missing.",
                type="negative",
            )
            return

        # Do not leave room passwords sitting in either hidden or visible inputs.
        self.create_password_input.value = ""
        self.join_password_input.value = ""
        self.generation += 1
        generation = self.generation
        self._set_busy(True)
        self.busy_label.set_text(
            "Negotiating TLS 1.3 and registering..."
            if mode is not Mode.PLAINTEXT
            else "Connecting to the plaintext baseline relay..."
        )

        try:
            client = await asyncio.to_thread(
                self._connect_worker,
                generation,
                relay_host,
                username,
                password,
                mode,
                room_name,
                room_code,
            )
        except Exception as exc:
            if generation != self.generation or self.status == "closed":
                return
            self._notify_connect_error(exc)
            self._set_busy(False)
            return

        if generation != self.generation or self.status == "closed":
            await asyncio.to_thread(_close_client, client)
            return

        self.client = client
        self.status = "connected"
        self.messages = []
        self.peer_names = set(client.peers)
        self.send_in_flight = False
        if room_name is not None:
            self._append_system(
                "Room created. Share the six-digit code only with intended participants."
            )
        else:
            self._append_system("Joined the room. Your connection is ready.")
        if mode is Mode.PLAINTEXT:
            self._append_system(
                "INSECURE baseline active: message content is not encrypted in transit."
            )
        elif mode is Mode.E2E:
            self._append_system(
                "Compare every peer fingerprint out of band and explicitly verify it before sending."
            )

        self._set_busy(False)
        self._drop_lobby_references()
        self.render_workspace.refresh()
        ui.notify(
            f"Connected to room {client.room_code}.", type="positive", timeout=3500
        )

    def _connect_worker(
        self,
        generation: int,
        relay_host: str,
        username: str,
        password: str,
        mode: Mode,
        room_name: str | None,
        room_code: str | None,
    ) -> ChatClient:
        """Perform blocking disk and network work away from NiceGUI's event loop."""

        identity: Identity | None = None
        trust_store: TrustStore | None = None
        identity_path: Path | None = None
        if mode is Mode.E2E:
            USER_DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Both paths are derived from a strictly validated username, so one
            # user's private identity and trust decisions cannot be reused by another.
            identity_path = USER_DATA / f"{username}.identity"
            trust_path = USER_DATA / f"{username}.trust.json"
            try:
                identity = Identity.load(identity_path)
            except FileNotFoundError:
                identity = None
            trust_store = TrustStore(trust_path)

        def on_event(event: dict[str, Any]) -> None:
            # This runs in ChatClient's background listener thread.
            self.events.put((generation, event))

        client = ChatClient(
            relay_host,
            username,
            password,
            mode,
            ca_file=CA_FILE,
            identity=identity,
            trust_store=trust_store,
            on_event=on_event,
        )
        try:
            client.connect(room_name=room_name, room_code=room_code)
            if mode is Mode.E2E:
                if client.identity is None or identity_path is None:
                    raise ChatClientError("E2E identity was not initialized")
                # ChatClient generates an identity when none exists. Persist only
                # after a successful connection, then own_fingerprint is available.
                client.identity.save(identity_path)
            if not client.connected:
                raise ChatClientError("relay closed during connection setup")
            # Registration is complete; the core never needs the password again.
            client.password = ""
            return client
        except Exception:
            _close_client(client)
            raise

    @staticmethod
    def _notify_connect_error(exc: Exception) -> None:
        if isinstance(exc, ssl.SSLCertVerificationError):
            message = (
                "TLS certificate verification failed. Check the relay hostname "
                "and ensure it is issued by certs/ca.crt."
            )
        elif isinstance(exc, ssl.SSLError):
            message = "TLS 1.3 negotiation failed. No insecure fallback was attempted."
        elif isinstance(exc, ChatClientError):
            detail = str(exc).strip()
            message = f"Connection rejected: {detail[:240]}" if detail else "Connection rejected by the relay."
        elif isinstance(exc, PermissionError):
            message = "Local identity or trust data could not be accessed safely."
        elif isinstance(exc, (socket.gaierror, ConnectionRefusedError, TimeoutError, OSError)):
            message = "Could not reach the relay. Check its address and confirm that it is already running."
        elif isinstance(exc, ValueError):
            message = "Local identity or trust data could not be loaded safely."
        else:
            message = "Connection failed safely. Check the room details and local security files."
        ui.notify(message, type="negative", timeout=6500, multi_line=True)

    def _drop_lobby_references(self) -> None:
        self.action_buttons = []
        self.busy_row = None
        self.busy_label = None
        self.mode_input = None
        self.username_input = None
        self.server_input = None
        self.room_name_input = None
        self.room_code_input = None
        self.create_password_input = None
        self.join_password_input = None

    def _render_chat(self) -> None:
        assert self.client is not None
        self.shell_element.classes(add="chat-active")
        self.workspace_element.classes(add="chat-active")
        client = self.client
        connected = self.status == "connected"

        with ui.element("div").classes("cx-chat-layout"):
            with ui.element("section").classes("cx-chat-panel"):
                with ui.element("div").classes("cx-chat-header"):
                    with ui.column().classes("gap-1 min-w-0"):
                        with ui.row().classes("items-center gap-2 flex-wrap"):
                            ui.label(client.room_name or "ChatreX room").classes("cx-room-name")
                            if connected:
                                ui.badge("CONNECTED", color="positive").classes("cx-status-pill cx-pill-connected")
                            else:
                                ui.badge("DISCONNECTED", color="negative").classes("cx-status-pill cx-pill-disconnected")
                        ui.label(
                            f"{client.username}  |  Relay {client.host}"
                        ).classes("cx-room-meta")
                        with ui.row().classes("items-center gap-2 mt-2 flex-wrap"):
                            self._active_mode_pill(client.mode)
                            ui.button(
                                "Leave room",
                                icon="logout",
                                on_click=self._leave,
                            ).props("flat dense no-caps").classes("text-red-300")

                    with ui.element("div").classes("cx-code-box"):
                        ui.label("ROOM CODE").classes("cx-code-label")
                        ui.label(client.room_code or "------").classes("cx-code")
                        ui.button(
                            icon="content_copy",
                            on_click=lambda: self._copy_text(
                                client.room_code or "", "Room code"
                            ),
                        ).props("flat round dense size=sm").classes("text-cyan-200")

                self.render_trust_notice()
                self.render_messages()

                with ui.element("div").classes("cx-composer"):
                    if client.mode is Mode.PLAINTEXT:
                        note = (
                            "INSECURE plaintext broadcast: the relay and network observers can read this message."
                        )
                        note_class = "cx-composer-note insecure"
                    elif client.mode is Mode.TLS:
                        note = "Broadcast over TLS 1.3. The network is protected, but the relay can read message content."
                        note_class = "cx-composer-note"
                    else:
                        note = (
                            "E2E sends individually with send_text() only after every current peer is verified. "
                            "Any unverified peer blocks sending; compare fingerprints out of band first."
                        )
                        note_class = "cx-composer-note"
                    ui.label(note).classes(note_class)
                    with ui.row().classes("w-full items-center gap-2 flex-nowrap"):
                        self.message_input = ui.input(
                            placeholder="Type a message..." if connected else "Disconnected from the relay"
                        ).classes("cx-field flex-1").props(
                            "dark outlined dense maxlength=65536 autocomplete=off spellcheck=false"
                        )
                        self.message_input.on("keydown.enter", self._send_message)
                        self.send_button = ui.button(
                            icon="send", on_click=self._send_message
                        ).classes("cx-send-button").props(
                            "color=primary text-color=dark unelevated"
                        )
                        if not connected:
                            self.message_input.disable()
                            self.send_button.disable()

            with ui.element("aside").classes("cx-sidebar"):
                self.render_identity()
                self.render_members()

    @staticmethod
    def _active_mode_pill(mode: Mode) -> None:
        if mode is Mode.PLAINTEXT:
            with ui.element("div").classes("cx-status-pill cx-pill-plain"):
                ui.icon("warning", size="14px")
                ui.label("INSECURE PLAINTEXT")
        elif mode is Mode.TLS:
            with ui.element("div").classes("cx-status-pill cx-pill-secure"):
                ui.icon("lock", size="14px")
                ui.label("TLS 1.3")
        else:
            with ui.element("div").classes("cx-status-pill cx-pill-connected"):
                ui.icon("verified_user", size="14px")
                ui.label("TLS 1.3 + X25519 E2E")

    @ui.refreshable
    def render_trust_notice(self) -> None:
        client = self.client
        if client is None or client.mode is not Mode.E2E:
            return
        peers = dict(client.peers)
        unverified = sorted(
            username for username in peers if not client.is_peer_verified(username)
        )
        if not peers:
            icon = "info"
            text = "You are the only room member. Sending becomes available after another member joins and their fingerprint is verified."
            ready = False
        elif unverified:
            icon = "gpp_maybe"
            text = (
                "Sending is blocked for unverified peers: "
                + ", ".join(unverified)
                + ". Compare each full fingerprint using a separate authenticated channel, then use the explicit verification action in the member list."
            )
            ready = False
        else:
            icon = "verified_user"
            text = f"All {len(peers)} peer identities are verified for this room. Messages will be encrypted individually for each recipient."
            ready = True
        with ui.element("div").classes("cx-trust-banner" + (" ready" if ready else "")):
            ui.icon(icon, size="19px").classes("mt-0.5")
            ui.label(text)

    @ui.refreshable
    def render_messages(self) -> None:
        scroll = ui.scroll_area().classes("cx-message-scroll w-full")
        with scroll:
            with ui.element("div").classes("cx-message-area"):
                if not self.messages:
                    with ui.element("div").classes("cx-empty-state"):
                        ui.icon("forum", size="34px").classes("text-slate-600 mb-3")
                        ui.label("No messages yet").classes("text-sm font-semibold text-slate-300")
                        ui.label("Room activity and secure messages will appear here.").classes("text-xs mt-1")
                for message in self.messages:
                    if message.system:
                        ui.label(message.text).classes("cx-system-message")
                        continue
                    with ui.element("div").classes("cx-message-row" + (" own" if message.own else "")):
                        with ui.element("div").classes("cx-message-wrap"):
                            with ui.element("div").classes("cx-message-meta"):
                                ui.label("You" if message.own else message.sender)
                                ui.label(message.time)
                            ui.label(message.text).classes("cx-message-bubble")
        scroll.scroll_to(percent=1.0)

    @ui.refreshable
    def render_identity(self) -> None:
        client = self.client
        if client is None:
            return
        with ui.element("section").classes("cx-side-panel"):
            with ui.element("div").classes("cx-side-heading"):
                ui.label("YOUR SECURITY IDENTITY").classes("cx-section-label")
                ui.icon("badge", size="18px").classes("text-cyan-300")
            with ui.element("div").classes("cx-own-identity"):
                with ui.row().classes("items-center gap-2"):
                    ui.icon("account_circle", size="21px").classes("text-cyan-200")
                    ui.label(client.username).classes("cx-member-name")
                    ui.badge("YOU", color="cyan").classes("ml-auto")
                if client.mode is Mode.E2E:
                    own_fingerprint = client.own_fingerprint
                    ui.label(
                        "Share this full fingerprint with peers through a separate authenticated channel."
                    ).classes("cx-member-status mt-2")
                    with ui.expansion("Full own fingerprint", icon="fingerprint").classes("w-full mt-2"):
                        if own_fingerprint:
                            ui.label(own_fingerprint).classes("cx-fingerprint")
                            ui.button(
                                "Copy full fingerprint",
                                icon="content_copy",
                                on_click=lambda: self._copy_text(
                                    own_fingerprint, "Own fingerprint"
                                ),
                            ).props("flat dense no-caps").classes("text-cyan-200 mt-2")
                        else:
                            ui.label(
                                "Identity unavailable. Leave and reconnect before using E2E."
                            ).classes("text-red-300 text-xs")
                else:
                    ui.label(
                        "X25519 identity fingerprints are created and used in E2E mode."
                    ).classes("cx-member-status mt-2")

    @ui.refreshable
    def render_members(self) -> None:
        client = self.client
        if client is None:
            return
        peers = dict(client.peers)
        with ui.element("section").classes("cx-side-panel"):
            with ui.element("div").classes("cx-side-heading"):
                ui.label("ROOM MEMBERS").classes("cx-section-label")
                ui.badge(str(len(peers) + 1), color="secondary")
            if not peers:
                ui.label(
                    "No other members yet. Share the room code with an intended participant."
                ).classes("cx-empty-members")
            for username, peer in sorted(peers.items()):
                verified = (
                    client.is_peer_verified(username)
                    if client.mode is Mode.E2E
                    else False
                )
                with ui.element("div").classes("cx-member-card"):
                    with ui.row().classes("items-center gap-2"):
                        ui.icon(
                            "verified_user" if verified else "person", size="20px"
                        ).classes("text-green-300" if verified else "text-slate-400")
                        ui.label(username).classes("cx-member-name")
                    if client.mode is not Mode.E2E:
                        ui.label("Connected room member").classes("cx-member-status mt-1")
                        continue

                    ui.label(
                        "Fingerprint verified" if verified else "Verification required before sending"
                    ).classes(
                        "cx-member-status mt-1 " + ("verified" if verified else "unverified")
                    )
                    with ui.expansion("Full peer fingerprint", icon="fingerprint").classes("w-full mt-1"):
                        fingerprint = peer.fingerprint
                        if fingerprint is None:
                            ui.label("No valid peer key is available.").classes("text-red-300 text-xs")
                            continue
                        ui.label(fingerprint).classes("cx-fingerprint")
                        ui.label(
                            "Compare every group out of band. Do not approve a fingerprint solely because it appears in this dashboard."
                        ).classes("cx-relay-note mt-2")
                        ui.button(
                            "Copy fingerprint",
                            icon="content_copy",
                            on_click=lambda value=fingerprint: self._copy_text(
                                value, "Peer fingerprint"
                            ),
                        ).props("flat dense no-caps").classes("text-cyan-200 mt-1")
                        if not verified:
                            ui.button(
                                "I compared this fingerprint out of band",
                                icon="how_to_reg",
                                on_click=lambda name=username: self._verify_peer(name),
                            ).classes("cx-verify-button").props(
                                "color=positive text-color=dark unelevated no-caps"
                            )

    def _verify_peer(self, username: str) -> None:
        client = self.client
        if client is None or self.status != "connected" or client.mode is not Mode.E2E:
            return
        try:
            verified = client.confirm_peer(username)
        except (OSError, ValueError):
            ui.notify(
                "Could not save this verification safely. No trust decision was changed.",
                type="negative",
            )
            return
        if not verified:
            ui.notify(
                "The peer or fingerprint changed. Compare the current fingerprint again.",
                type="warning",
            )
        else:
            ui.notify(
                f"Verified {username}'s fingerprint for this room.", type="positive"
            )
            self._append_system(
                f"You explicitly verified {username}'s E2E fingerprint out of band."
            )
            self.render_messages.refresh()
        self.render_members.refresh()
        self.render_trust_notice.refresh()

    async def _send_message(self) -> None:
        client = self.client
        if (
            client is None
            or self.status != "connected"
            or not client.connected
            or self.send_in_flight
            or self.message_input is None
        ):
            return
        text = self.message_input.value or ""
        if not text.strip():
            return
        if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
            ui.notify("Message exceeds the 65,536-byte protocol limit.", type="warning")
            return

        if client.mode is Mode.E2E:
            peers = dict(client.peers)
            if not peers:
                ui.notify(
                    "Message not sent: there are no other room members.",
                    type="warning",
                )
                return
            unverified = sorted(
                username
                for username in peers
                if not client.is_peer_verified(username)
            )
            if unverified:
                ui.notify(
                    "Message not sent. E2E requires explicit out-of-band verification "
                    "for every peer. Unverified: " + ", ".join(unverified),
                    type="warning",
                    timeout=6500,
                    multi_line=True,
                )
                return

        generation = self.generation
        self.send_in_flight = True
        self._update_send_controls()
        try:
            # With no recipients argument, ChatClient broadcasts in Plain/TLS
            # and seals separately for each peer in E2E. Its trust checks remain
            # the final authority if a roster changes during this await.
            await asyncio.to_thread(client.send_text, text)
        except TrustError:
            ui.notify(
                "Message blocked because a current E2E peer is not verified.",
                type="warning",
            )
        except (ChatClientError, OSError, ValueError):
            ui.notify(
                "Message could not be sent. Check the connection and try again.",
                type="negative",
            )
        except Exception:
            ui.notify("Message could not be sent safely.", type="negative")
        else:
            if generation == self.generation and self.client is client:
                self.message_input.value = ""
                self.messages.append(
                    DisplayMessage(client.username, text, _now(), own=True)
                )
                if len(self.messages) > MAX_DISPLAYED_MESSAGES:
                    self.messages = self.messages[-MAX_DISPLAYED_MESSAGES:]
                self.render_messages.refresh()
        finally:
            self.send_in_flight = False
            if generation == self.generation and self.client is client:
                self._update_send_controls()

    def _update_send_controls(self) -> None:
        disabled = self.send_in_flight or self.status != "connected"
        for element in (self.message_input, self.send_button):
            if element is None:
                continue
            if disabled:
                element.disable()
            else:
                element.enable()

    def _poll_events(self) -> None:
        while True:
            try:
                generation, event = self.events.get_nowait()
            except queue.Empty:
                break
            if generation != self.generation or self.client is None:
                continue
            kind = event.get("kind")
            if kind == "disconnected":
                self._remote_disconnected()
                break
            if self.status != "connected":
                continue
            if kind == "message":
                self._receive_message(event)
            elif kind == "roster":
                self._receive_roster(event)
            elif kind == "error":
                detail = str(event.get("message", "Relay error"))[:240]
                self._append_system(f"Relay error: {detail}")
                self.render_messages.refresh()
                ui.notify(detail, type="negative", timeout=5000)

    def _receive_message(self, event: dict[str, Any]) -> None:
        payload = event.get("payload")
        sender = str(event.get("from", "Unknown"))
        if not isinstance(payload, bytes):
            self._append_system("Discarded a malformed incoming message.")
        else:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                self._append_system(
                    f"Discarded a non-UTF-8 message from {sender}; this console accepts text only."
                )
            else:
                self.messages.append(
                    DisplayMessage(
                        sender,
                        text,
                        _now(),
                        own=sender == (self.client.username if self.client else None),
                    )
                )
        if len(self.messages) > MAX_DISPLAYED_MESSAGES:
            self.messages = self.messages[-MAX_DISPLAYED_MESSAGES:]
        self.render_messages.refresh()

    def _receive_roster(self, event: dict[str, Any]) -> None:
        raw_peers = event.get("peers", {})
        current = set(raw_peers) if isinstance(raw_peers, dict) else set()
        for username in sorted(current - self.peer_names):
            self._append_system(f"{username} joined the room. E2E trust must be verified explicitly.")
        for username in sorted(self.peer_names - current):
            self._append_system(f"{username} left the room. Their room-scoped trust pin was removed.")
        self.peer_names = current
        self.render_members.refresh()
        self.render_trust_notice.refresh()
        self.render_messages.refresh()

    def _remote_disconnected(self) -> None:
        if self.client is None or self.status != "connected":
            return
        self.status = "disconnected"
        self.generation += 1
        self.client.password = ""
        self.send_in_flight = False
        self._append_system("Disconnected from the relay. Sending is disabled.")
        self.render_workspace.refresh()
        ui.notify(
            "Disconnected from the relay. Review the room or leave to reconnect.",
            type="negative",
            timeout=5500,
        )

    def _leave(self) -> None:
        client = self.client
        self.generation += 1
        self.client = None
        self.status = "idle"
        self.messages = []
        self.peer_names = set()
        self.send_in_flight = False
        self.message_input = None
        self.send_button = None
        if client is not None:
            _close_client(client)
        self.render_workspace.refresh()
        ui.notify("Left the room. Room credentials were not saved.", type="info")

    def _page_disconnected(self) -> None:
        self.generation += 1
        client = self.client
        self.client = None
        self.status = "closed"
        if client is not None:
            _close_client(client)

    def _append_system(self, text: str) -> None:
        self.messages.append(DisplayMessage("SYSTEM", text, _now(), system=True))
        if len(self.messages) > MAX_DISPLAYED_MESSAGES:
            self.messages = self.messages[-MAX_DISPLAYED_MESSAGES:]

    @staticmethod
    def _copy_text(text: str, label: str) -> None:
        if not text:
            return
        ui.clipboard.write(text)
        ui.notify(f"{label} copied to the clipboard.", type="positive", timeout=2000)


_DEFAULT_RELAY_HOST = DEFAULT_RELAY_HOST


@ui.page("/")
def index() -> None:
    """Build isolated controller state for every browser page load."""

    DashboardController(_DEFAULT_RELAY_HOST).build()


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ChatreX NiceGUI dashboard.")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web UI bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Web UI port (default: 8081)",
    )
    parser.add_argument(
        "--relay-host",
        default=DEFAULT_RELAY_HOST,
        help=f"Default chat relay hostname or IPv4 address (default: {DEFAULT_RELAY_HOST})",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535")
    try:
        args.relay_host = _normalized_relay_host(
            args.relay_host, DEFAULT_RELAY_HOST
        )
    except ValueError:
        parser.error("--relay-host must be a valid IPv4 address or DNS hostname")
    return args


def main(argv: Sequence[str] | None = None) -> None:
    """Start only NiceGUI; never install packages or launch a relay."""

    global _DEFAULT_RELAY_HOST
    args = _parse_args(argv)
    _DEFAULT_RELAY_HOST = args.relay_host
    ui.run(
        host=args.host,
        port=args.port,
        title="CHATREX | Security Dashboard",
        dark=True,
        reload=False,
        show=False,
        show_welcome_message=False,
    )


if __name__ == "__main__":
    main()
