# sing_box_config_generator_final_v26.py
"""
Sing-box Config Maker - KivyMD Edition (Final Patched Version)

- [UI FIX] Set proxy list cards to an adaptive height to prevent long Geo-IP info from being cut off.
- [FIX] Changed WireGuard checker to a fast DNS lookup.
- [FIX] Added a fallback Geo-IP service (ipinfo.io) for the SOCKS5 checker.
- [FIX] Disabled the main action bar on Settings/Log tabs.
"""

import os
import json
import re
import threading
import time
import socket
import base64
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
import weakref
from datetime import datetime
import webbrowser

# --- Dependency Management ---
try:
    import requests
    import socks
    import urllib3 # Explicitly import to help packaging tools
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False

from kivy.core.clipboard import Clipboard
from kivy.clock import Clock
from kivy.properties import ObjectProperty
from kivy.storage.jsonstore import JsonStore
from kivy.core.window import Window

from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.gridlayout import MDGridLayout
from kivymd.uix.textfield import MDTextField
from kivymd.uix.button import MDRaisedButton, MDIconButton, MDFlatButton
from kivymd.uix.label import MDLabel
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import MDList, OneLineIconListItem
from kivymd.uix.menu import MDDropdownMenu
from kivymd.uix.tab import MDTabs, MDTabsBase
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.card import MDCard
from kivymd.uix.selectioncontrol import MDCheckbox


# --- Data Classes ---
@dataclass
class AddedProxy:
    """Holds the state for each added proxy configuration."""
    ptype: str
    label: str
    data: dict
    raw: str = ""
    selected: bool = True
    status: str = "Idle"
    latency: str = "N/A"
    info: str = "N/A"
    _ui_widget_ref: weakref.ref = field(default=None, repr=False)

    @property
    def ui_widget(self):
        return self._ui_widget_ref() if self._ui_widget_ref else None

    @ui_widget.setter
    def ui_widget(self, widget):
        self._ui_widget_ref = weakref.ref(widget) if widget else None


# --- Core Parsing & Network Functions ---
def _decode_vmess(url: str) -> dict:
    try:
        payload = url.split("://", 1)[1]
        missing = len(payload) % 4
        if missing: payload += "=" * (4 - missing)
        obj = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "ignore"))
        return {"server": obj.get("add", ""), "server_port": int(obj.get("port", 0) or 0), "uuid": obj.get("id", ""), "alter_id": int(obj.get("aid", 0) or 0), "security": obj.get("scy") or "auto", "transport": obj.get("net") or "tcp", "sni": obj.get("sni") or obj.get("host") or "", "path": obj.get("path") or "", "header": obj.get("type") or "", "tls": (obj.get("tls") or "").lower() in ("tls", "reality", "xtls")}
    except Exception: return {}

def _decode_vless(url: str) -> dict:
    try:
        u = urlparse(url)
        user = unquote(u.username or ""); host = u.hostname or ""; port = int(u.port or 0); qs = parse_qs(u.query)
        return {"server": host, "server_port": port, "uuid": user, "flow": (qs.get("flow", [None])[0]) or "", "transport": (qs.get("type", [None])[0]) or "tcp", "sni": (qs.get("sni", [None])[0]) or "", "path": (qs.get("path", [None])[0]) or "", "tls": (qs.get("security", [None])[0] or "").lower() in ("tls", "reality", "xtls")}
    except Exception: return {}

def _decode_shadowsocks(url: str) -> dict:
    try:
        u = urlparse(url); host = u.hostname or ""; port = int(u.port or 0); userinfo = u.netloc.split("@")[0]
        if ":" not in userinfo:
            missing = len(userinfo) % 4
            if missing: userinfo += "=" * (4 - missing)
            userinfo = base64.urlsafe_b64decode(userinfo.encode()).decode("utf-8", "ignore")
        method, password = userinfo.split(":", 1)
        return {"server": host, "server_port": port, "method": method, "password": password}
    except Exception: return {}
    
def parse_socks_string(s: str):
    m = re.match(r"^\s*([\w\.\-]+):(\d+)(?::([^:\s]+):([^:\s]+))?\s*$", (s or "").strip());
    if not m: return None
    return {"server": m.group(1), "server_port": int(m.group(2)), "username": m.group(3) or "", "password": m.group(4) or ""}

def _tcp_ping_host(host: str, port: int, timeout=10.0):
    """
    Performs a TCP connection test to a given host and port.
    Returns a tuple of (latency_in_ms, resolved_ip_or_error_message).
    """
    try:
        ip = socket.gethostbyname(host)
        start_time = time.time()
        with socket.create_connection((ip, int(port)), timeout=timeout):
            end_time = time.time()
            return (end_time - start_time) * 1000, ip
    except socket.timeout:
        return float('inf'), "Timeout"
    except ConnectionRefusedError:
        return float('inf'), "Connection Refused"
    except socket.gaierror:
        return float('inf'), "Host Not Found"
    except Exception as e:
        return float('inf'), str(e).splitlines()[0]

def detect_proxy_type(s: str):
    s = (s or "").strip()
    if not s: return "unknown"
    if s.startswith("[Interface]") or "PrivateKey" in s: return "wireguard"
    ls = s.lower()
    if ls.startswith("vmess://"): return "vmess"
    if ls.startswith("vless://"): return "vless"
    if ls.startswith("ss://"): return "shadowsocks"
    try:
        parsed = urlparse(s if "://" in s else "//" + s); scheme = (parsed.scheme or "").lower(); netloc = parsed.netloc or parsed.path
        if scheme in ("socks5", "socks", "socks5h"): return "socks5"
        if scheme in ("http", "https"): return "http"
        if netloc:
            if "@" in netloc or re.match(r"^[\w\.\-]+:\d+$", netloc): return "socks5"
    except Exception: pass
    if re.match(r"^\s*([\w\.\-]+):(\d+)(?::([^:\s]+):([^:\s]+))?\s*$", s): return "socks5"
    return "unknown"

def parse_wireguard_conf(text: str) -> dict:
    out = {"private_key": "", "local_address": [], "peer_public_key": "", "server": "", "server_port": ""}
    lines = (text or "").splitlines()
    for L in lines:
        if "=" not in L: continue
        key, val = L.split("=", 1); key, val = key.strip(), val.strip()
        if key == "PrivateKey": out["private_key"] = val
        if key == "Address": out["local_address"] = [a.strip() for a in re.split(r"[,\s]+", val) if a.strip()]
        if key == "PublicKey": out["peer_public_key"] = val
        if key == "Endpoint":
            match_ipv6 = re.match(r'\[(.*)\]:(\d+)', val)
            if match_ipv6: out["server"] = match_ipv6.group(1); out["server_port"] = int(match_ipv6.group(2))
            elif ':' in val.rsplit(']', 1)[-1]:
                host, port = val.rsplit(":", 1); out["server"] = host.strip()
                try: out["server_port"] = int(port.strip())
                except (ValueError, TypeError): out["server_port"] = ""
            else: out["server"] = val
    return out

def _outbound_from_added(outbound_tag_for_type, p) -> dict:
    t = p.ptype.lower(); server_id = p.data.get("server") or "proxy"; tag = f"{outbound_tag_for_type(t).split('-')[0]}-{server_id}"
    if t == "wireguard":
        d = p.data; sp = int(d.get("server_port") or 51820); local_addrs = [a.strip() for a in (d.get("local_address") or "").split(",") if a.strip()]
        return {"type":"wireguard","tag":tag,"interface_name":"wg0", "local_address": local_addrs or ["10.74.200.203/32"], "private_key": d.get("private_key",""), "peers":[{"server": d.get("server",""), "server_port": sp, "public_key": d.get("peer_public_key",""), "allowed_ips":["0.0.0.0/0","::/0"]}], "mtu":1420}
    if t in ("socks5","http","https"):
        d = p.data; ob = {"type":"socks" if t=="socks5" else t,"tag":tag,"server": d.get("server",""), "server_port": int(d.get("server_port") or 0)}
        if d.get("username"): ob["username"] = d.get("username"); ob["password"] = d.get("password","")
        return ob
    if t == "vmess":
        d = _decode_vmess(p.raw);
        if not d: return {}; tag = f"VMESS-{d.get('server', 'proxy')}"
        ob = {"type":"vmess","tag":tag,"server":d["server"],"server_port":d["server_port"], "uuid":d["uuid"],"alter_id": d.get("alter_id",0),"security": d.get("security","auto")}
        if d.get("tls"): ob["tls"] = {"enabled": True, "server_name": d.get("sni") or ""};
        if d.get("transport") in ("ws","grpc","quic","http"): ob["transport"] = {"type": d.get("transport"), "path": d.get("path","")}
        return ob
    if t == "vless":
        d = _decode_vless(p.raw);
        if not d: return {}; tag = f"VLESS-{d.get('server', 'proxy')}"
        ob = {"type":"vless","tag":tag,"server":d["server"],"server_port":d["server_port"],"uuid":d["uuid"],"flow": d.get("flow","")}
        if d.get("tls"): ob["tls"] = {"enabled": True, "server_name": d.get("sni") or ""};
        if d.get("transport") in ("ws","grpc","quic","http"): ob["transport"] = {"type": d.get("transport"), "path": d.get("path","")}
        return ob
    if t == "shadowsocks":
        d = _decode_shadowsocks(p.raw);
        if not d: return {}; tag = f"SS-{d.get('server', 'proxy')}"
        return {"type":"shadowsocks","tag":tag,"server":d["server"],"server_port":d["server_port"], "method": d["method"], "password": d["password"]}
    return {}

def outbound_tag_for_type(proxy_type: str):
    t = (proxy_type or "").lower()
    if t == "wireguard": return "WG-US";
    if t == "socks5": return "SOCKS5-PROXY"
    if t == "vmess": return "VMESS-PROXY";
    if t == "vless": return "VLESS-PROXY"
    if t == "shadowsocks": return "SS-PROXY";
    if t == "http": return "HTTP-PROXY"
    return "PROXY"

# --- KivyMD UI Components ---

class Tab(MDBoxLayout, MDTabsBase): pass

class ProxyDetailWidget(MDCard):
    proxy = ObjectProperty(None)
    def __init__(self, proxy_obj: AddedProxy, **kwargs):
        super().__init__(**kwargs)
        self.proxy = proxy_obj
        self.proxy.ui_widget = self
        self.orientation = 'vertical'
        self.size_hint_y = None
        # [UI FIX] Make card height adaptive to fit all content
        self.adaptive_height = True
        self.padding = "8dp"
        self.elevation = 3
        self.style = "filled"
        self.padding = ("8dp", "8dp", "8dp", "12dp")
        self.radius = [12]

        main_row = MDBoxLayout(adaptive_height=True, spacing="10dp")
        self.cb_select = MDCheckbox(active=self.proxy.selected, size_hint_x=None, width="48dp")
        self.cb_select.bind(active=self._on_selection_change)
        self.lbl_label = MDLabel(text=self.proxy.label, font_style="Subtitle1", adaptive_height=True, shorten=True, shorten_from='right')
        main_row.add_widget(self.cb_select)
        main_row.add_widget(self.lbl_label)

        action_row = MDBoxLayout(adaptive_height=True, spacing="5dp", padding=("8dp", 0), size_hint_x=None, width="150dp")
        self.btn_edit = MDIconButton(icon="pencil", on_press=self._on_edit)
        self.btn_check = MDIconButton(icon="flash", on_press=self._on_check)
        self.btn_delete = MDIconButton(icon="delete", on_press=self._on_delete)
        action_row.add_widget(self.btn_edit)
        action_row.add_widget(self.btn_check)
        action_row.add_widget(self.btn_delete)
        main_row.add_widget(action_row)

        status_grid = MDGridLayout(cols=2, adaptive_height=True, padding=("48dp", "8dp", 0, "8dp"), spacing=("10dp", "5dp"))
        
        status_grid.add_widget(MDLabel(text="Status:", font_style="Caption", bold=True, adaptive_height=True))
        self.lbl_status = MDLabel(font_style="Caption", adaptive_height=True)
        
        status_grid.add_widget(MDLabel(text="Latency:", font_style="Caption", bold=True, adaptive_height=True))
        self.lbl_latency = MDLabel(font_style="Caption", adaptive_height=True)
        
        status_grid.add_widget(MDLabel(text="Info:", font_style="Caption", bold=True, adaptive_height=True))
        # [UI FIX] Allow info label to wrap instead of shortening
        self.lbl_info = MDLabel(font_style="Caption", adaptive_height=True)

        status_grid.add_widget(self.lbl_status)
        status_grid.add_widget(self.lbl_latency)
        status_grid.add_widget(self.lbl_info)

        self.add_widget(main_row)
        self.add_widget(status_grid)
        self.update_ui()

    def _on_selection_change(self, instance, value): self.proxy.selected = value; self.update_ui(); MDApp.get_running_app().save_state()
    def _on_check(self, instance): MDApp.get_running_app().root.check_proxy(self.proxy)
    def _on_edit(self, instance): MDApp.get_running_app().root.edit_proxy(self.proxy)
    def _on_delete(self, instance): MDApp.get_running_app().root.confirm_delete_proxy(self.proxy)
    
    def update_ui(self):
        self.lbl_label.text = self.proxy.label
        self.lbl_status.text = self.proxy.status
        self.lbl_latency.text = self.proxy.latency
        self.lbl_info.text = self.proxy.info
        self.btn_check.disabled = (self.proxy.status == "Checking...")
        self.cb_select.active = self.proxy.selected
        
        if self.proxy.status == "Reachable":
            self.lbl_status.theme_text_color = "Primary" 
        elif self.proxy.status in ["Unreachable", "Error"]:
            self.lbl_status.theme_text_color = "Error"
        else:
            self.lbl_status.theme_text_color = "Secondary"

class MainScreen(MDScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.added_proxies = []; self.generated_config = ""; self.dns_protection_on = False; self.dialog = None
        root_layout = MDBoxLayout(orientation='vertical', spacing='10dp')
        header = MDBoxLayout(adaptive_height=True, spacing="10dp", padding=("10dp", "10dp", "10dp", 0))
        header.add_widget(MDLabel(text="Sing-Box Configurator", font_style="H6", adaptive_height=True))
        root_layout.add_widget(header)
        self.tab_panel = MDTabs(background_color=self.theme_cls.primary_color)
        self.tab_panel.bind(on_tab_switch=self.on_tab_switch)
        
        # --- Add Proxy Tab ---
        self.tab_add_proxy = Tab(title="Add Proxy")
        add_proxy_scroll = MDScrollView()
        add_proxy_content = MDBoxLayout(orientation="vertical", adaptive_height=True, spacing="15dp", padding="15dp")
        
        self.paste_input = MDTextField(
            hint_text="Paste any proxy string or config here",
            mode="rectangle"
        )
        add_proxy_content.add_widget(self.paste_input)

        paste_actions = MDGridLayout(cols=2, adaptive_height=True, spacing="8dp")
        paste_actions.add_widget(MDRaisedButton(text="Detect & Parse", on_press=self.on_detect_and_parse))
        paste_actions.add_widget(MDRaisedButton(text="Import WG Conf File", on_press=self.on_import_wg_conf))
        paste_actions.add_widget(MDRaisedButton(text="Batch Import Links", on_press=self.on_batch_import))
        add_proxy_content.add_widget(paste_actions)
        self.proxy_type_button = MDRaisedButton(text="WireGuard")
        self.proxy_type_button.bind(on_release=self.open_proxy_menu)
        proxy_types = ["WireGuard", "SOCKS5", "VMess", "VLESS", "Shadowsocks", "HTTP"]
        menu_items = [{"text": f"{i}", "viewclass": "OneLineIconListItem", "on_release": lambda x=f"{i}": self.set_proxy_type(x)} for i in proxy_types]
        self.proxy_menu = MDDropdownMenu(caller=self.proxy_type_button, items=menu_items, width_mult=4)
        add_proxy_content.add_widget(self.proxy_type_button)
        self.wg_grid = MDGridLayout(cols=1, adaptive_height=True, spacing="10dp")
        self.wg_server = MDTextField(hint_text="WG Host/Endpoint"); self.wg_port = MDTextField(hint_text="WG Port"); self.wg_private_key = MDTextField(hint_text="Private Key"); self.wg_local_address = MDTextField(hint_text="Local Address (e.g., 10.0.0.2/32)"); self.wg_peer_public_key = MDTextField(hint_text="Peer Public Key")
        self.wg_grid.add_widget(self.wg_server); self.wg_grid.add_widget(self.wg_port); self.wg_grid.add_widget(self.wg_private_key); self.wg_grid.add_widget(self.wg_local_address); self.wg_grid.add_widget(self.wg_peer_public_key)
        self.proxy_grid = MDGridLayout(cols=1, adaptive_height=True, spacing="10dp")
        self.proxy_host = MDTextField(hint_text="Proxy Host"); self.proxy_port = MDTextField(hint_text="Proxy Port"); self.proxy_user = MDTextField(hint_text="Username (optional)"); self.proxy_pass = MDTextField(hint_text="Password (optional)")
        self.proxy_grid.add_widget(self.proxy_host); self.proxy_grid.add_widget(self.proxy_port); self.proxy_grid.add_widget(self.proxy_user); self.proxy_grid.add_widget(self.proxy_pass)
        self.add_proxy_form_container = MDBoxLayout(orientation='vertical', adaptive_height=True)
        add_proxy_content.add_widget(self.add_proxy_form_container)
        self.btn_add_proxy = MDRaisedButton(text="Add From Form", on_press=self.add_current_proxy, pos_hint={'center_x': 0.5})
        add_proxy_content.add_widget(self.btn_add_proxy)
        add_proxy_scroll.add_widget(add_proxy_content); self.tab_add_proxy.add_widget(add_proxy_scroll); self.tab_panel.add_widget(self.tab_add_proxy)
        
        # --- Proxy List Tab ---
        self.tab_proxy_list = Tab(title="Proxy List")
        proxy_list_layout = MDBoxLayout(orientation='vertical', padding="10dp", spacing="10dp")
        self.proxies_list_container = MDList(); proxies_scroll = MDScrollView(); proxies_scroll.add_widget(self.proxies_list_container)
        proxy_list_layout.add_widget(proxies_scroll); self.tab_proxy_list.add_widget(proxy_list_layout); self.tab_panel.add_widget(self.tab_proxy_list)
        
        # --- Settings Tab ---
        self.tab_settings = Tab(title="Settings")
        settings_content = MDBoxLayout(orientation="vertical", spacing="15dp", padding="20dp")
        dns_row = MDBoxLayout(adaptive_height=True, spacing="10dp"); dns_row.add_widget(MDLabel(text="DNS Protection", adaptive_height=True, halign="left"))
        self.dns_switch = MDCheckbox(active=self.dns_protection_on, size_hint_x=None, width="48dp"); self.dns_switch.bind(active=self.toggle_dns)
        dns_row.add_widget(self.dns_switch)
        settings_content.add_widget(dns_row)
        
        theme_row = MDBoxLayout(adaptive_height=True, spacing="10dp"); theme_row.add_widget(MDLabel(text="App Theme", adaptive_height=True, halign="left"))
        self.theme_button = MDRaisedButton(text="Theme: Dark", on_press=self.open_theme_menu)
        theme_row.add_widget(self.theme_button)
        settings_content.add_widget(theme_row)

        contact_row = MDBoxLayout(adaptive_height=True, spacing="10dp")
        contact_row.add_widget(MDLabel(text="Support", adaptive_height=True, halign="left"))
        contact_row.add_widget(MDRaisedButton(text="Contact Developer", on_press=self.contact_developer))
        settings_content.add_widget(contact_row)

        self.tab_settings.add_widget(settings_content); self.tab_panel.add_widget(self.tab_settings)
        
        # --- Log Tab ---
        self.tab_log = Tab(title="Log")
        log_layout = MDBoxLayout(orientation='vertical', padding="10dp")
        log_scroll = MDScrollView()
        self.log_output = MDTextField(multiline=True, readonly=True, hint_text="Application logs will appear here...", size_hint_y=None)
        self.log_output.bind(minimum_height=self.log_output.setter('height'))
        log_scroll.add_widget(self.log_output)
        log_layout.add_widget(log_scroll)
        self.tab_log.add_widget(log_layout)
        self.tab_panel.add_widget(self.tab_log)

        root_layout.add_widget(self.tab_panel)
        self.action_bar = MDBoxLayout(adaptive_height=True, spacing="8dp", padding=("10dp", "10dp", "10dp", "20dp"))
        self.action_bar.add_widget(MDRaisedButton(text="Generate", on_press=self.generate_config, md_bg_color=self.theme_cls.primary_color)); self.action_bar.add_widget(MDRaisedButton(text="View", on_press=self.view_config)); self.action_bar.add_widget(MDRaisedButton(text="Copy", on_press=self.copy_config)); self.action_bar.add_widget(MDRaisedButton(text="Save", on_press=self.save_config))
        root_layout.add_widget(self.action_bar); self.add_widget(root_layout)
        Clock.schedule_once(self.post_build_init)

    def log_message(self, message):
        """Appends a timestamped message to the log view and prints to console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        print(log_entry.strip())
        Clock.schedule_once(lambda dt: self._update_log_text(log_entry))

    def _update_log_text(self, log_entry):
        self.log_output.text += log_entry
        self.log_output.cursor = (0, len(self.log_output.text))


    def post_build_init(self, dt):
        self.set_proxy_type("WireGuard")
        self.log_message("Application initialized.")

    def open_proxy_menu(self, instance): self.proxy_menu.open()
    def set_proxy_type(self, text_item):
        self.proxy_type_button.text = text_item; self.proxy_menu.dismiss(); ptype = text_item.lower().replace(" ", "")
        self.add_proxy_form_container.clear_widgets()
        if ptype == 'wireguard': self.add_proxy_form_container.add_widget(self.wg_grid)
        elif ptype in ('socks5', 'http'): self.add_proxy_form_container.add_widget(self.proxy_grid)

    def open_theme_menu(self, instance):
        themes = ["Light", "Dark", "Maroon"]
        menu_items = [{"text": theme, "viewclass": "OneLineListItem", "on_release": lambda x=theme: self.change_theme(x)} for theme in themes]
        MDDropdownMenu(caller=instance, items=menu_items, width_mult=4).open()

    def change_theme(self, theme_style):
        app = MDApp.get_running_app()
        if theme_style == "Maroon":
            app.theme_cls.theme_style = "Dark"
            app.theme_cls.primary_palette = "Red"
            app.theme_cls.primary_hue = "800"
        else:
            app.theme_cls.theme_style = theme_style
            app.theme_cls.primary_palette = "BlueGray"
        
        self.theme_button.text = f"Theme: {theme_style}"
        self.log_message(f"Theme changed to {theme_style}.")

    def contact_developer(self, instance):
        webbrowser.open("https://t.me/sir10ma")
        self.log_message("Opened developer contact link.")

    def show_dialog(self, title, message):
        try:
            if self.dialog: self.dialog.dismiss()
        except Exception: pass
        self.dialog = MDDialog(title=title, text=message, buttons=[MDFlatButton(text="OK", on_release=lambda x: self.dialog.dismiss())])
        self.dialog.open()

    def show_dialog_with_content(self, title, content_cls, buttons=None):
        try:
            if self.dialog: self.dialog.dismiss()
        except Exception: pass
        self.dialog = MDDialog(title=title, type="custom", content_cls=content_cls, buttons=buttons or [MDFlatButton(text="OK", on_release=lambda x: self.dialog.dismiss())])
        self.dialog.open()
        
    def switch_to_tab(self, tab_name):
        try:
            for tab in self.tab_panel.get_tab_list():
                if hasattr(tab, 'title') and tab.title == tab_name:
                    self.tab_panel.switch_tab(tab)
                    return
        except Exception as e:
            self.log_message(f"Error switching tab: {e}")

    def on_tab_switch(self, instance_tabs, instance_tab, instance_tab_label, tab_text):
        """Handles visibility of the action bar based on the current tab."""
        if tab_text in ["Settings", "Log"]:
            self.action_bar.height = 0
            self.action_bar.opacity = 0
            self.action_bar.disabled = True
        else:
            self.action_bar.height = "68dp"
            self.action_bar.opacity = 1
            self.action_bar.disabled = False

    def on_detect_and_parse(self, instance):
        txt = (self.paste_input.text or "").strip()
        if not txt:
            self.show_dialog("Error", "Paste input is empty.")
            return
        
        self.log_message(f"Detecting and parsing pasted text...")
        detected_type = detect_proxy_type(txt)
        
        if detected_type in ["vmess", "vless", "shadowsocks"]:
            self.log_message(f"Detected {detected_type} link.")
            if self.add_proxy_from_string(txt):
                self.show_dialog("Success", f"Added '{self.added_proxies[-1].label}' to the list.")
                self.refresh_added_list(); self.switch_to_tab("Proxy List"); self.paste_input.text = ""
            else: self.show_dialog("Error", "Could not parse the proxy link.")

        elif detected_type == "wireguard":
            self.log_message("Detected WireGuard config.")
            self.set_proxy_type("WireGuard")
            wg = parse_wireguard_conf(txt)
            if not wg.get("private_key"):
                 self.show_dialog("Parse Failed", "Could not find a PrivateKey in the pasted text.")
                 self.log_message("WireGuard parse failed: PrivateKey not found.")
                 return
            self.wg_server.text = wg.get("server", ""); self.wg_port.text = str(wg.get("server_port", "")); self.wg_private_key.text = wg.get("private_key", ""); self.wg_local_address.text = ",".join(wg.get("local_address", [])); self.wg_peer_public_key.text = wg.get("peer_public_key", "")
            self.show_dialog("Parsed", "WireGuard config parsed into the form.")
            self.log_message("Successfully parsed WireGuard config into form.")
            self.switch_to_tab("Add Proxy"); self.paste_input.text = ""

        elif detected_type in ("socks5", "http"):
            self.log_message(f"Detected {detected_type} string.")
            parsed_data = None
            if detected_type == "socks5":
                parsed_data = parse_socks_string(txt)
            elif detected_type == "http":
                try:
                    u = urlparse(txt if "://" in txt else f"{detected_type}://" + txt)
                    parsed_data = {"server": u.hostname or "", "server_port": int(u.port or 0), "username": u.username or "", "password": u.password or ""}
                except (ValueError, TypeError):
                    parsed_data = None

            if parsed_data and parsed_data.get("server"):
                self.set_proxy_type(detected_type.upper())
                self.proxy_host.text = parsed_data.get("server", ""); self.proxy_port.text = str(parsed_data.get("server_port", "")); self.proxy_user.text = parsed_data.get("username", ""); self.proxy_pass.text = parsed_data.get("password", "")
                self.show_dialog("Parsed", f"{detected_type.upper()} config parsed into the form.")
                self.log_message(f"Successfully parsed {detected_type.upper()} config into form.")
                self.switch_to_tab("Add Proxy"); self.paste_input.text = ""
            else:
                self.show_dialog("Parse Failed", f"Could not parse the {detected_type.upper()} string.")
                self.log_message(f"Failed to parse {detected_type.upper()} string.")
        
        else:
            self.show_dialog("Detection Failed", "Could not determine the proxy type from the pasted text.")
            self.log_message("Could not detect proxy type from pasted text.")

    def on_import_wg_conf(self, instance):
        content_box = MDBoxLayout(orientation="vertical", adaptive_height=True)
        scroll = MDScrollView(size_hint_y=None, height="300dp")
        conf_paste_input = MDTextField(multiline=True, hint_text="Paste WireGuard config here", size_hint_y=None)
        conf_paste_input.bind(minimum_height=conf_paste_input.setter('height'))
        scroll.add_widget(conf_paste_input)
        content_box.add_widget(scroll)

        self.show_dialog_with_content("Import WireGuard Config", content_box, [
            MDFlatButton(text="CANCEL", on_release=lambda x: self.dialog.dismiss()),
            MDFlatButton(text="PARSE", on_release=lambda x: self._parse_wg_from_dialog(conf_paste_input.text))
        ])

    def _parse_wg_from_dialog(self, text):
        self.dialog.dismiss()
        txt = (text or "").strip()
        if not txt: self.show_dialog("Error", "Paste box was empty."); return
        self.log_message("Parsing WireGuard config from dialog...")
        detected_type = detect_proxy_type(txt)
        if detected_type == "wireguard":
            self.set_proxy_type("WireGuard")
            wg = parse_wireguard_conf(txt)
            self.wg_server.text = wg.get("server", ""); self.wg_port.text = str(wg.get("server_port", "")); self.wg_private_key.text = wg.get("private_key", ""); self.wg_local_address.text = ",".join(wg.get("local_address", [])); self.wg_peer_public_key.text = wg.get("peer_public_key", "")
            self.show_dialog("Parsed", "WireGuard config parsed into the form.")
            self.log_message("Successfully parsed WireGuard config from dialog.")
            self.switch_to_tab("Add Proxy")
        else:
            self.show_dialog("Detection Failed", "Pasted text is not a valid WireGuard config.")
            self.log_message("Failed to parse WG config from dialog: Not a valid config.")

    def on_batch_import(self, instance):
        batch_input = MDTextField(multiline=True, hint_text="Paste one proxy link per line")
        self.show_dialog_with_content("Batch Import", batch_input, [MDFlatButton(text="CANCEL", on_release=lambda x: self.dialog.dismiss()), MDFlatButton(text="IMPORT", on_release=lambda x: self.import_links(batch_input.text))])

    def import_links(self, text):
        self.dialog.dismiss(); links = text.strip().splitlines(); added_count = sum(1 for link in links if self.add_proxy_from_string(link))
        self.refresh_added_list(); self.show_dialog("Success", f"Added {added_count} proxies.")
        self.log_message(f"Batch imported {added_count} proxies.")

    def add_proxy_from_string(self, text: str) -> bool:
        s = text.strip();
        if not s: return False
        ptype = detect_proxy_type(s)
        if ptype not in ["unknown", "wireguard", "socks5", "http"]:
            decoded = _decode_vmess(s) or _decode_vless(s) or _decode_shadowsocks(s) or {}
            if not decoded: return False
            label = f"{ptype.upper()} {decoded.get('server') or '(Pasted)'}"
            self.added_proxies.append(AddedProxy(ptype=ptype, label=label, data={}, raw=s))
            self.log_message(f"Added proxy from string: {label}")
            return True
        return False
        
    def clear_form_inputs(self):
        for field in [self.wg_server, self.wg_port, self.wg_private_key, self.wg_local_address, self.wg_peer_public_key]:
            field.text = ""
        for field in [self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_pass]:
            field.text = ""

    def add_current_proxy(self, instance=None):
        ptype = self.proxy_type_button.text.lower().replace(" ", ""); proxy_added = False; label = ""
        if ptype == "wireguard":
            if not (self.wg_private_key.text.strip() and self.wg_server.text.strip()): self.show_dialog("Error", "Provide WG PrivateKey and Host."); return
            data = {"private_key": self.wg_private_key.text.strip(), "server": self.wg_server.text.strip(), "server_port": int(self.wg_port.text.strip() or 51820), "peer_public_key": self.wg_peer_public_key.text.strip(), "local_address": self.wg_local_address.text.strip()}
            label = f"WG {data['server']}:{data['server_port']}"; self.added_proxies.append(AddedProxy(ptype="wireguard", label=label, data=data)); proxy_added = True
        elif ptype in ("socks5", "http"):
            if not (self.proxy_host.text.strip() and self.proxy_port.text.strip()): self.show_dialog("Error", "Enter host and port."); return
            data = {"server": self.proxy_host.text.strip(), "server_port": int(self.proxy_port.text.strip() or 0), "username": self.proxy_user.text.strip(), "password": self.proxy_pass.text.strip()}
            label = f"{ptype.upper()} {data['server']}:{data['server_port']}"; self.added_proxies.append(AddedProxy(ptype=ptype, label=label, data=data)); proxy_added = True
        else: self.show_dialog("Error", f"Cannot add '{ptype}' from form. Please use the paste buttons."); return
        if proxy_added: 
            self.log_message(f"Added proxy from form: {label}")
            self.refresh_added_list(); self.show_dialog("Added", f"'{label}' added to list.")
            self.clear_form_inputs()

    def refresh_added_list(self):
        self.proxies_list_container.clear_widgets()
        for p in self.added_proxies: self.proxies_list_container.add_widget(ProxyDetailWidget(proxy_obj=p))
        MDApp.get_running_app().save_state()
        
    def confirm_delete_proxy(self, proxy_to_remove):
        self.show_dialog_with_content(
            "Delete Proxy?",
            MDLabel(text="This action cannot be undone."),
            [
                MDFlatButton(text="CANCEL", on_release=lambda x: self.dialog.dismiss()),
                MDRaisedButton(text="DELETE", on_release=lambda x: self.remove_proxy(proxy_to_remove))
            ]
        )

    def remove_proxy(self, proxy_to_remove: AddedProxy): 
        self.dialog.dismiss()
        self.log_message(f"Removed proxy: {proxy_to_remove.label}")
        self.added_proxies.remove(proxy_to_remove); self.refresh_added_list()

    def check_proxy(self, proxy: AddedProxy):
        proxy.status = "Checking..."; proxy.latency = "..."; proxy.info = "..."; 
        if proxy.ui_widget:
            Clock.schedule_once(lambda dt: proxy.ui_widget.update_ui())
        threading.Thread(target=self._worker_check_proxy, args=(proxy,), daemon=True).start()

    def _worker_check_proxy(self, proxy: AddedProxy):
        app = MDApp.get_running_app()
        ptype = proxy.ptype.lower()
        d = proxy.data
        host, port = None, None
        
        if not DEPENDENCIES_AVAILABLE:
            proxy.status = "Error"
            proxy.info = "requests/socks module missing in APK"
            if proxy.ui_widget: Clock.schedule_once(lambda dt: proxy.ui_widget.update_ui())
            self.log_message(f"Check failed for {proxy.label}: Dependency missing.")
            return

        self.log_message(f"Checking proxy: {proxy.label} ({proxy.ptype})")

        try:
            if ptype in ('socks5', 'http', 'wireguard'):
                host, port = d.get('server'), d.get('server_port')
            elif ptype in ('vmess', 'vless', 'shadowsocks'):
                decoded = {
                    'vmess': _decode_vmess, 'vless': _decode_vless, 'shadowsocks': _decode_shadowsocks
                }[ptype](proxy.raw)
                host, port = decoded.get('server'), decoded.get('server_port')

            if not host or not port:
                raise Exception("Invalid Host/Port in config")

            if ptype in ('socks5', 'http'):
                self.log_message(f"-> Performing Geo-IP check for {host}:{port}...")
                try:
                    proxy_url = f"{'socks5h' if ptype == 'socks5' else 'http'}://"
                    if d.get("username") and d.get("password"): 
                        proxy_url += f"{d.get('username')}:{d.get('password')}@"
                    proxy_url += f"{host}:{port}"
                    proxies = {"http": proxy_url, "https": proxy_url}
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                    
                    start_time = time.time()
                    api_url = "https://ip-api.com/json/?fields=status,message,country,regionName,query"
                    response = requests.get(api_url, proxies=proxies, headers=headers, timeout=15, verify=False)
                    latency_ms = (time.time() - start_time) * 1000
                    response.raise_for_status()
                    api_data = response.json()

                    if api_data.get("status") != "success": raise Exception("API 1 Error")
                    
                    proxy.info = f"{api_data.get('country', 'N/A')}, {api_data.get('regionName', 'N/A')} - {api_data.get('query', 'N/A')}"
                    proxy.status = "Reachable"
                    proxy.latency = f"{latency_ms:.0f}ms"
                    self.log_message(f"-> Geo-IP Success (API 1) for {proxy.label}: {proxy.info}")

                except Exception as e1:
                    self.log_message(f"-> API 1 failed: {e1}. Trying fallback...")
                    try:
                        start_time = time.time()
                        api_url = "https://ipinfo.io/json"
                        response = requests.get(api_url, proxies=proxies, headers=headers, timeout=15, verify=False)
                        latency_ms = (time.time() - start_time) * 1000
                        response.raise_for_status()
                        api_data = response.json()
                        proxy.info = f"{api_data.get('country', 'N/A')}, {api_data.get('region', 'N/A')} - {api_data.get('ip', 'N/A')}"
                        proxy.status = "Reachable"
                        proxy.latency = f"{latency_ms:.0f}ms"
                        self.log_message(f"-> Geo-IP Success (API 2) for {proxy.label}: {proxy.info}")
                    except Exception as e2:
                        self.log_message(f"-> All Geo-IP checks failed for {proxy.label}: {e2}. Falling back to TCP ping.")
                        latency_ms, resolved_ip = _tcp_ping_host(host, int(port))
                        if latency_ms == float('inf'): raise Exception(resolved_ip)
                        proxy.status = "Reachable"
                        proxy.latency = f"{latency_ms:.0f}ms"
                        proxy.info = f"Resolved IP: {resolved_ip}"
            
            elif ptype == 'wireguard':
                self.log_message(f"-> Resolving DNS for WireGuard endpoint {host}...")
                start_time = time.time()
                try:
                    resolved_ip = socket.gethostbyname(host)
                    latency_ms = (time.time() - start_time) * 1000
                    proxy.status = "Reachable"
                    proxy.latency = f"{latency_ms:.0f}ms (DNS)"
                    proxy.info = f"Endpoint IP: {resolved_ip}"
                    self.log_message(f"-> DNS Success for {proxy.label}: {proxy.info}")
                except socket.gaierror:
                    raise Exception("Host Not Found")

            else: 
                latency_ms, resolved_ip = _tcp_ping_host(host, int(port))
                if latency_ms == float('inf'):
                    raise Exception(resolved_ip)
                proxy.status = "Reachable"
                proxy.latency = f"{latency_ms:.0f}ms"
                proxy.info = f"Resolved IP: {resolved_ip}"
                self.log_message(f"-> Ping Success for {proxy.label}. Latency: {proxy.latency}")

        except Exception as e:
            proxy.status = "Unreachable"
            proxy.latency = "N/A"
            error_message = str(e).splitlines()[0]
            proxy.info = f"Error: {error_message}"
            self.log_message(f"-> Failure for {proxy.label}. Reason: {error_message}")

        if proxy.ui_widget:
            Clock.schedule_once(lambda dt: proxy.ui_widget.update_ui())
            
    def generate_config(self, instance=None):
        outbounds = [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns-out"}]; proxy_tags = []; final_outbound_tag = "direct"; selected_proxies = [p for p in self.added_proxies if p.selected]
        if selected_proxies:
            for p in selected_proxies:
                ob = _outbound_from_added(outbound_tag_for_type, p)
                if ob: outbounds.append(ob); proxy_tags.append(ob["tag"])
            if proxy_tags: selector = {"type": "selector", "tag": "PROXY-SELECTOR", "outbounds": proxy_tags + ["direct"], "default": proxy_tags[0]}; outbounds.append(selector); final_outbound_tag = "PROXY-SELECTOR"
            self.show_dialog("Generated", f"Config created with {len(proxy_tags)} proxies.")
            self.log_message(f"Generated config with {len(proxy_tags)} proxies.")
        else: self.show_dialog("Generated", "Direct-only config generated.")
        dns_detour = final_outbound_tag if self.dns_protection_on else "dns-out"
        config_template = {"log": {"level": "error"}, "dns": {"servers": [{"tag": "cloudflare", "address": "https://1.1.1.1/dns-query", "detour": dns_detour}], "strategy": "prefer_ipv4"}, "inbounds": [{"type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 9898, "sniff": True}], "outbounds": outbounds, "route": {"rules": [{"protocol": "dns", "outbound": "dns-out"}], "final": final_outbound_tag}, "experimental": {"clash_api": {"external_controller": "0.0.0.0:9090"}}}
        self.generated_config = json.dumps(config_template, indent=2)

    def view_config(self, instance):
        if not self.generated_config: self.show_dialog("Error", "No config generated yet."); return
        content_box = MDBoxLayout(orientation="vertical", adaptive_height=True)
        scroll = MDScrollView(size_hint_y=None, height="400dp")
        text_field = MDTextField(text=self.generated_config, multiline=True, readonly=True, size_hint_y=None)
        text_field.bind(minimum_height=text_field.setter('height'))
        scroll.add_widget(text_field)
        content_box.add_widget(scroll)
        self.show_dialog_with_content("Generated config.json", content_box)

    def copy_config(self, instance):
        if not self.generated_config: self.show_dialog("Error", "No config to copy."); return
        Clipboard.copy(self.generated_config); self.show_dialog("Copied", "Config copied to clipboard.")
        self.log_message("Config copied to clipboard.")

    def save_config(self, instance):
        if not self.generated_config: self.show_dialog("Error", "No config generated yet."); return
        try:
            save_path = os.path.join(MDApp.get_running_app().user_data_dir, "box_config.json")
            with open(save_path, "w", encoding="utf-8") as f: f.write(self.generated_config)
            self.show_dialog("Saved", f"Saved to {save_path}")
            self.log_message(f"Config saved to {save_path}")
        except Exception as e:
            self.show_dialog("Error", f"Failed to save: {e}")
            self.log_message(f"Error saving config: {e}")

    def toggle_dns(self, instance, value):
        self.dns_protection_on = value
        self.log_message(f"DNS Protection turned {'ON' if value else 'OFF'}.")

    def edit_proxy(self, proxy: AddedProxy):
        content = MDTextField(text=proxy.raw if proxy.raw else json.dumps(proxy.data, indent=2), multiline=True)
        self.show_dialog_with_content(f"Edit {proxy.label}", content, [MDFlatButton(text="CANCEL", on_release=lambda x: self.dialog.dismiss()), MDFlatButton(text="SAVE", on_release=lambda x: self.save_proxy_edit(proxy, content.text))])
    
    def save_proxy_edit(self, proxy, text):
        self.dialog.dismiss()
        ptype = proxy.ptype.lower()
        try:
            original_label = proxy.label
            if proxy.raw: # For link-based proxies
                proxy.raw = text.strip()
                decoded = {}
                if ptype == "vmess": decoded = _decode_vmess(proxy.raw)
                elif ptype == "vless": decoded = _decode_vless(proxy.raw)
                elif ptype == "shadowsocks": decoded = _decode_shadowsocks(proxy.raw)
                if decoded.get('server'): 
                    proxy.label = f"{ptype.upper()} {decoded.get('server')}"
            else: # For form-based proxies
                proxy.data = json.loads(text)
                if proxy.data.get('server'): 
                    proxy.label = f"{ptype.upper()} {proxy.data.get('server')}"
            self.log_message(f"Edited proxy '{original_label}' to '{proxy.label}'.")
            self.refresh_added_list()
        except Exception as e:
            self.show_dialog("Error", f"Invalid format for edit: {e}")
            self.log_message(f"Failed to save proxy edit: {e}")

class SingboxApp(MDApp):
    def build(self):
        self.title = "Sing-box Config Maker"; self.theme_cls.primary_palette = "BlueGray"; self.theme_cls.accent_palette = "Amber"; self.theme_cls.theme_style = "Dark"
        self.store = JsonStore(os.path.join(self.user_data_dir, 'settings.json'))
        Window.bind(on_request_close=self.handle_back_button)
        return MainScreen()

    def handle_back_button(self, *args, **kwargs):
        """Handles the back button press for natural navigation."""
        main_screen = self.root
        if main_screen.dialog:
            main_screen.dialog.dismiss()
            return True
        if main_screen.tab_panel.get_current_tab() != main_screen.tab_add_proxy:
            main_screen.switch_to_tab("Add Proxy")
            return True
        return False

    def on_start(self):
        if self.store.exists('settings'):
            settings = self.store.get('settings')
            theme_style = settings.get('theme_style', 'Dark')
            self.root.change_theme(theme_style)
            dns_on = settings.get('dns_on', False)
            self.root.dns_protection_on = dns_on
            self.root.dns_switch.active = dns_on
            proxies_data = settings.get('proxies', [])
            main_screen = self.root
            main_screen.added_proxies.clear()
            for p_data in proxies_data:
                p_data.pop('_ui_widget_ref', None)
                main_screen.added_proxies.append(AddedProxy(**p_data))
            main_screen.refresh_added_list()
            self.root.log_message("Loaded saved state from settings.")

    def save_state(self):
        main_screen = self.root
        proxies_data = []
        for p in main_screen.added_proxies:
            p_dict = p.__dict__.copy()
            p_dict.pop('_ui_widget_ref', None) 
            proxies_data.append(p_dict)
        
        self.store.put('settings',
            theme_style=self.theme_cls.theme_style,
            dns_on=main_screen.dns_protection_on,
            proxies=proxies_data
        )

    def on_stop(self):
        self.root.log_message("Application stopping. Saving state.")
        self.save_state()

if __name__ == "__main__":
    SingboxApp().run()
