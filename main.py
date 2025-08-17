# sing_config_maker.py
"""
Sing-Box Configurator - v4.3 (Crash Fix Release)
"""

# --- Logging Setup ---
import sys
import os
import traceback

# Path where logs will be written (external storage)
LOG_FILE = "/sdcard/singbox_log.txt"

# Ensure the directory exists
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except Exception:
    pass

# Redirect stdout and stderr to the log file
sys.stdout = open(LOG_FILE, "w", buffering=1)   # line-buffered
sys.stderr = sys.stdout

# Optional: catch uncaught exceptions and write them
def excepthook(exc_type, exc_value, exc_traceback):
    traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)

sys.excepthook = excepthook

print("🔹 Logging started. Any errors will be written here:", LOG_FILE)

# --- Standard Library Imports ---
import os
import json
import re
import threading
import socket
import base64
import webbrowser
import subprocess
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, unquote
# --- Third-party Library Imports ---
import requests
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# --- KivyMD Imports ---
from kivymd.app import MDApp
from kivymd.uix.toolbar import MDTopAppBar
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.label import MDLabel
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.menu import MDDropdownMenu
from kivymd.uix.card import MDCard
from kivymd.uix.list import OneLineListItem

# --- Kivy Imports ---
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.utils import platform
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.checkbox import CheckBox
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner

# --- Widget Aliases & Helpers ---
Label = MDLabel
TextInput = MDTextField
Button = MDRaisedButton

class Tab(MDBottomNavigationItem):
    def __init__(self, content=None, **kwargs):
        super().__init__(**kwargs)
        if content: self.add_widget(content)

@dataclass
class AddedProxy:
    ptype: str; label: str; data: dict; raw: str = ""; selected: bool = True

# --- All Helper Functions (decoding, parsing, theming etc.) ---
def _decode_vmess(url: str) -> dict:
    try:
        payload = url.split("://",1)[1]; missing = len(payload) % 4
        if missing: payload += "=" * (4-missing)
        obj = json.loads(base64.urlsafe_b64decode(payload.encode()).decode("utf-8","ignore"))
        return {"server": obj.get("add",""), "server_port": int(obj.get("port",0) or 0), "uuid": obj.get("id",""), "alter_id": int(obj.get("aid",0) or 0), "security": obj.get("scy") or "auto", "transport": obj.get("net") or "tcp", "sni": obj.get("sni") or obj.get("host") or "", "path": obj.get("path") or "", "tls": (obj.get("tls") or "").lower() in ("tls","reality","xtls")}
    except Exception: return {}

def _decode_vless(url: str) -> dict:
    try:
        u = urlparse(url); qs = parse_qs(u.query)
        return {"server": u.hostname or "", "server_port": int(u.port or 0), "uuid": unquote(u.username or ""), "flow": (qs.get("flow",[None])[0]) or "", "transport": (qs.get("type",[None])[0]) or "tcp", "sni": (qs.get("sni",[None])[0]) or "", "path": (qs.get("path",[None])[0]) or "", "tls": (qs.get("security",[None])[0] or "").lower() in ("tls","reality","xtls")}
    except Exception: return {}

def _decode_shadowsocks(url: str) -> dict:
    try:
        u = urlparse(url); userinfo = u.netloc.split("@")[0]
        if ":" not in userinfo:
            missing = len(userinfo) % 4
            if missing: userinfo += "="*(4-missing)
            userinfo = base64.urlsafe_b64decode(userinfo.encode()).decode("utf-8","ignore")
        method, password = userinfo.split(":",1)
        return {"server": u.hostname or "", "server_port": int(u.port or 0), "method": method, "password": password}
    except Exception: return {}

def _outbound_from_added(outbound_tag_for_type, p) -> dict:
    t = p.ptype.lower(); tag = outbound_tag_for_type(t)
    if t == "wireguard":
        d = p.data; sp = int(d.get("server_port") or 51820)
        local_addrs = [a.strip() for a in (d.get("local_address") or "").split(",") if a.strip()]
        return {"type":"wireguard","tag":tag,"interface_name":"wg0","local_address": local_addrs or ["10.74.200.203/32"],"private_key": d.get("private_key",""),"peers":[{"server": d.get("server",""), "server_port": sp, "public_key": d.get("peer_public_key",""),"allowed_ips":["0.0.0.0/0","::/0"]}],"mtu":1420}
    if t in ("socks5","http","https"):
        d = p.data; ob = {"type":"socks" if t=="socks5" else t,"tag":tag,"server": d.get("server",""),"server_port": int(d.get("server_port") or 0)}
        if d.get("username"): ob["username"] = d.get("username"); ob["password"] = d.get("password","")
        return ob
    if t == "vmess":
        d = _decode_vmess(p.raw);
        if not d: return {}
        ob = {"type":"vmess","tag":tag,"server":d["server"],"server_port":d["server_port"],"uuid":d["uuid"],"alter_id": d.get("alter_id",0),"security": d.get("security","auto")}
        if d.get("tls"): ob["tls"] = {"enabled": True, "server_name": d.get("sni") or ""};
        if d.get("transport") in ("ws","grpc","quic","http"): ob["transport"] = {"type": d.get("transport"), "path": d.get("path","")}
        return ob
    return {}

def _tcp_ping_host(host: str, port: int, timeout=4.0):
    try: ip = socket.gethostbyname(host); socket.create_connection((ip, int(port)), timeout=timeout); return True, ip
    except Exception as e: return False, str(e)

def _icmp_ping_host(host: str):
    param = '-n' if platform == 'win32' else '-c'
    timeout_param = '-w' if platform != 'win32' else '-W'
    command = ['ping', param, '1', timeout_param, '3', host]
    try:
        subprocess.run(command, capture_output=True, text=True, check=True, timeout=5)
        return True, host
    except FileNotFoundError: return False, "Ping command not found."
    except subprocess.TimeoutExpired: return False, "Ping timed out."
    except subprocess.CalledProcessError: return False, "Host unreachable."
    except Exception as e: return False, f"An error occurred: {e}"

try:
    if platform not in ('android','ios'): Window.size = (450, 800)
except Exception: pass

THEMES = {"Default": {"bg": (0.06, 0.36, 0.76, 1), "fg": (1, 1, 1, 1), "btn": (0.12, 0.28, 0.72, 1)},"Green": {"bg": (0.06, 0.45, 0.28, 1), "fg": (1, 1, 1, 1), "btn": (0.0, 0.7, 0.4, 1)},"Maroon": {"bg": (0.45, 0.08, 0.08, 1), "fg": (1, 1, 1, 1), "btn": (0.7, 0.18, 0.18, 1)},"Lavender": {"bg": (0.88, 0.86, 0.94, 1), "fg": (0.06, 0.06, 0.06, 1), "btn": (0.64, 0.58, 0.78, 1)}}
current_theme = "Default"

def scale_size(base_size: int) -> int:
    try: factor = Window.width / 720.0
    except Exception: factor = 1.0
    return max(10, int(round(base_size * factor)))

def _compute_input_bg(bg):
    return (min(1.0, bg[0] * 0.92 + 0.08), min(1.0, bg[1] * 0.92 + 0.08), min(1.0, bg[2] * 0.92 + 0.08), 1.0)

def recolor_widget_recursively(w, theme):
    try:
        if isinstance(w, Label): w.color = theme["fg"]
        if isinstance(w, Button): w.background_normal = ''; w.md_bg_color = theme["btn"]; w.theme_text_color = "Custom"; w.text_color = theme["fg"]
        if isinstance(w, TextInput): w.text_color_normal = theme["fg"]; w.fill_color_normal = _compute_input_bg(theme["bg"])
        if isinstance(w, MDBottomNavigation): w.panel_color = theme["btn"]
        if isinstance(w, OneLineListItem): w.theme_text_color = "Custom"; w.text_color = theme["fg"]
    except Exception: pass
    for c in getattr(w, "children", []): recolor_widget_recursively(c, theme)

def apply_theme(name, app_instance):
    global current_theme
    if name not in THEMES: return
    current_theme = name; theme = THEMES[name]; Window.clearcolor = theme["bg"]
    if app_instance and app_instance.root:
        recolor_widget_recursively(app_instance.root, theme)

def detect_proxy_type(s: str):
    s = (s or "").strip();
    if not s: return "unknown"
    if s.startswith("[Interface]") or "PrivateKey" in s: return "wireguard"
    ls = s.lower()
    if ls.startswith("vmess://"): return "vmess"
    if ls.startswith("vless://"): return "vless"
    if ls.startswith("ss://"): return "shadowsocks"
    try:
        parsed = urlparse(s if "://" in s else "//" + s); scheme = (parsed.scheme or "").lower(); netloc = parsed.netloc or parsed.path
        if scheme in ("socks5", "socks", "socks5h"): return "socks5"
        if netloc and ("@" in netloc or re.match(r"^[\w\.\-]+:\d+$", netloc)): return "socks5"
    except Exception: pass
    return "unknown"

def parse_socks_string(s: str):
    s = (s or "").strip()
    m = re.match(
        r"^(?:(?P<user>[^:@]+)(?::(?P<pass>[^@]+))?@)?(?P<host>[^:]+):(?P<port>\d+)$",
        s
    )
    if not m:
        if '://' in s:
            s = s.split('://', 1)[1]
            m = re.match(
                r"^(?:(?P<user>[^:@]+)(?::(?P<pass>[^@]+))?@)?(?P<host>[^:]+):(?P<port>\d+)$",
                s
            )
        if not m:
            return None
    groups = m.groupdict()
    return {
        "server": groups.get("host") or "",
        "port": int(groups.get("port") or 0),
        "username": groups.get("user") or "",
        "password": groups.get("pass") or ""
    }

def parse_wireguard_conf(text: str):
    out = {"private_key": "", "local_address": [], "peer_public_key": "", "server": "", "server_port": ""}
    for L in (text or "").splitlines():
        if L.strip().startswith("PrivateKey"): out["private_key"] = L.split("=", 1)[1].strip()
        if L.strip().startswith("Address"): out["local_address"] = [a.strip() for a in re.split(r"[,\s]+", L.split("=", 1)[1].strip()) if a.strip()]
        if L.strip().startswith("PublicKey"): out["peer_public_key"] = L.split("=", 1)[1].strip()
        if L.strip().startswith("Endpoint"):
            ep = L.split("=", 1)[1].strip()
            if ":" in ep:
                host, port = ep.rsplit(":", 1); out["server"] = host.strip()
                try: out["server_port"] = int(port.strip())
                except: out["server_port"] = ""
            else: out["server"] = ep
    return out

def outbound_tag_for_type(proxy_type: str):
    t = (proxy_type or "").lower()
    tags = {"wireguard": "WG", "socks5": "SOCKS5", "vmess": "VMESS", "vless": "VLESS", "shadowsocks": "SS", "direct": "direct"}
    return tags.get(t, "PROXY")

def small_popup(title, message, width=0.9, height=0.6):
    theme = THEMES.get(current_theme, THEMES["Default"]); content = MDBoxLayout(orientation="vertical", spacing=6, padding=6, md_bg_color=theme["bg"]); scroll = ScrollView(size_hint=(1, 1)); lbl = Label(text=message, font_size=scale_size(13), size_hint_y=None); lbl.bind(texture_size=lambda inst, size: setattr(inst, "height", float(size[1]))); recolor_widget_recursively(lbl, theme); scroll.add_widget(lbl); content.add_widget(scroll); ok = Button(text="OK", size_hint=(1, None), height=scale_size(40)); recolor_widget_recursively(ok, theme); popup = Popup(title=title, content=content, size_hint=(width, height), background_color=theme["bg"]); ok.bind(on_release=popup.dismiss); content.add_widget(ok); popup.open()

_PROXY_TYPE_MAP = {"WireGuard": "wireguard", "SOCKS5": "socks5", "VMess": "vmess", "VLESS": "vless", "Shadowsocks": "shadowsocks"}

class MainUI(MDBoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.added_proxies, self.generated_config = [], ""
        self.app = MDApp.get_running_app()
        self.build_menus()
        self.nav_panel = MDBottomNavigation()
        self.nav_panel.add_widget(Tab(content=self.build_add_proxy_tab(), name='add_proxy', text='Add Proxy', icon='plus-thick'))
        self.nav_panel.add_widget(Tab(content=self.build_proxy_list_tab(), name='proxy_list', text='Proxy List', icon='format-list-bulleted'))
        self.nav_panel.add_widget(Tab(content=self.build_settings_tab(), name='settings', text='Settings', icon='cog'))
        self.add_widget(self.nav_panel)
        self.add_widget(self.build_bottom_bar())
        self._on_proxy_type_select("WireGuard")
        Clock.schedule_once(self.load_state)
        # <<< FIX: Crash on exit resolved >>>
        Window.bind(on_request_close=self.save_state)

    def build_menus(self):
        proxy_menu_items = [{"text": f"{name}", "viewclass": "OneLineListItem", "on_release": lambda x=f"{name}": self.set_proxy_type(x)} for name in _PROXY_TYPE_MAP.keys()]
        self.proxy_type_menu = MDDropdownMenu(caller=self, items=proxy_menu_items, width_mult=4)

    def set_proxy_type(self, text_item):
        self.proxy_type_button.text = text_item; self._on_proxy_type_select(text_item); self.proxy_type_menu.dismiss()
    
    def open_theme_popup(self, button):
        content = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing=dp(10), padding=dp(10))
        scroll = ScrollView(); content.add_widget(scroll)
        grid = GridLayout(cols=1, size_hint_y=None); grid.bind(minimum_height=grid.setter('height')); scroll.add_widget(grid)
        popup = Popup(title="Select Theme", content=content, size_hint=(0.8, 0.7))
        for theme_name in THEMES.keys():
            # Diagnostic print statement to confirm this loop runs.
            # print(f"Creating theme button: {theme_name}")
            btn = Button(text=theme_name, size_hint_y=None, height=dp(48))
            btn.bind(on_release=lambda *args, name=theme_name: self.set_theme(name, popup))
            grid.add_widget(btn)
        recolor_widget_recursively(content, THEMES[current_theme])
        popup.open()
        
    def set_theme(self, text_item, popup):
        self.theme_button.text = text_item; apply_theme(text_item, self.app); popup.dismiss()

    def build_add_proxy_tab(self):
        root = ScrollView(); content = MDBoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(15), padding=dp(15), adaptive_height=True); root.add_widget(content)
        self.paste_input = TextInput(hint_text="Paste any proxy string or config here", multiline=False)
        content.add_widget(self.paste_input)
        button_row1 = MDBoxLayout(spacing=10, adaptive_height=True)
        button_row1.add_widget(Button(text="Detect & Parse", on_press=self.on_parse_paste))
        button_row1.add_widget(Button(text="Import WG Conf", on_press=self.on_import_wg))
        content.add_widget(button_row1)
        # <<< FIX: Dropdown crash resolved >>>
        self.proxy_type_button = Button(text="WireGuard"); self.proxy_type_button.bind(on_release=lambda x: self.proxy_type_menu.open())
        self.proxy_type_menu.caller = self.proxy_type_button
        content.add_widget(self.proxy_type_button)
        self.form_container = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing=dp(15)); content.add_widget(self.form_container)
        self.wg_form = self._create_wg_form(); self.socks_form = self._create_socks_form()
        content.add_widget(Button(text="Add To Proxy List", on_press=self.add_proxy_from_form, size_hint_y=None, height=dp(48)))
        return root

    def _on_proxy_type_select(self, proxy_name):
        try:
            self.form_container.clear_widgets()
            if proxy_name == "WireGuard":
                self.form_container.add_widget(self.wg_form)
            elif proxy_name == "SOCKS5":
                self.form_container.add_widget(self.socks_form)
        except Exception as e:
            print(f"Error switching forms: {e}")
            small_popup("UI Error", "An error occurred while switching the proxy form.")

    def _create_wg_form(self):
        form = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing=dp(15))
        self.wg_server = TextInput(hint_text="WG Host/Endpoint"); self.wg_port = TextInput(hint_text="WG Port"); self.wg_private_key = TextInput(hint_text="Private Key"); self.wg_local_address = TextInput(hint_text="Local Address (e.g., 10.0.0.2/32)"); self.wg_peer_public_key = TextInput(hint_text="Peer Public Key")
        for w in [self.wg_server, self.wg_port, self.wg_private_key, self.wg_local_address, self.wg_peer_public_key]: form.add_widget(w)
        return form

    def _create_socks_form(self):
        form = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing=dp(15))
        self.proxy_host = TextInput(hint_text="Proxy Host/IP"); self.proxy_port = TextInput(hint_text="Proxy Port"); self.proxy_user = TextInput(hint_text="Username (optional)"); self.proxy_pass = TextInput(hint_text="Password (optional)")
        for w in [self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_pass]: form.add_widget(w)
        return form

    def build_proxy_list_tab(self):
        root = ScrollView()
        self.proxies_list = GridLayout(cols=1, size_hint_y=None, spacing=dp(8), padding=dp(8)); self.proxies_list.bind(minimum_height=self.proxies_list.setter("height"))
        root.add_widget(self.proxies_list)
        return root

    def build_settings_tab(self):
        root = ScrollView(); content = MDBoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(20), padding=dp(20), adaptive_height=True); root.add_widget(content)
        appearance_card = MDCard(orientation='vertical', padding=dp(15), spacing=dp(10), adaptive_height=True)
        appearance_card.add_widget(Label(text="Appearance", font_style="H6", adaptive_height=True))
        theme_box = MDBoxLayout(adaptive_height=True, spacing=dp(10))
        theme_box.add_widget(Label(text="Theme", adaptive_size=True))
        self.theme_button = Button(text=current_theme, size_hint=(1, None), height=dp(48)); self.theme_button.bind(on_release=self.open_theme_popup)
        theme_box.add_widget(self.theme_button)
        appearance_card.add_widget(theme_box); content.add_widget(appearance_card)
        network_card = MDCard(orientation='vertical', padding=dp(15), spacing=dp(10), adaptive_height=True)
        network_card.add_widget(Label(text="Network", font_style="H6", adaptive_height=True))
        dns_box = MDBoxLayout(adaptive_height=True, spacing=dp(10))
        dns_box.add_widget(Label(text="DNS Protection", adaptive_size=True))
        self.dns_toggle_btn = Button(text="OFF", on_press=self.toggle_dns, size_hint=(1, None), height=dp(44))
        self.dns_protection_on = False
        dns_box.add_widget(self.dns_toggle_btn); network_card.add_widget(dns_box); content.add_widget(network_card)
        return root

    def build_bottom_bar(self):
        bar = MDBoxLayout(size_hint_y=None, adaptive_height=True, padding=dp(10), spacing=dp(10))
        self.btn_generate = Button(text="Generate", on_press=self.generate_config); self.btn_view = Button(text="View", on_press=self.view_config); self.btn_copy = Button(text="Copy", on_press=self.copy_config); self.btn_save = Button(text="Save", on_press=self.save_config)
        for btn in [self.btn_generate, self.btn_view, self.btn_copy, self.btn_save]: bar.add_widget(btn)
        return bar
        
    def add_proxy_from_form(self, instance):
        ptype = _PROXY_TYPE_MAP.get(self.proxy_type_button.text)
        if not ptype:
            return small_popup("Error", "Invalid proxy type selected.")
        self.add_current_proxy(ptype)
        if ptype == "wireguard":
            for field in [self.wg_server, self.wg_port, self.wg_private_key, self.wg_local_address, self.wg_peer_public_key]:
                field.text = ""
        elif ptype == "socks5":
            for field in [self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_pass]:
                field.text = ""

    def on_parse_paste(self, instance):
        txt = (self.paste_input.text or "").strip()
        if not txt: return small_popup("Error", "Paste a proxy string first.")
        detected = detect_proxy_type(txt)
        if detected == "unknown": return small_popup("Detection Failed", "Could not determine proxy type.")
        spinner_text = next((k for k, v in _PROXY_TYPE_MAP.items() if v == detected), None)
        if spinner_text: self.set_proxy_type(spinner_text)
        if detected == "wireguard": self._parse_and_populate_wg_form(txt)
        elif detected == "socks5":
            parsed = parse_socks_string(txt)
            if parsed:
                self.proxy_host.text, self.proxy_port.text, self.proxy_user.text, self.proxy_pass.text = parsed["server"], str(parsed["port"]), parsed.get("username", ""), parsed.get("password", "")
                small_popup("Parsed", "SOCKS5 details parsed. Review and click 'Add To Proxy List'.")
            else:
                small_popup("Parse Failed", "Could not parse SOCKS5 string. Check the format.")
        else: self.add_current_proxy(detected)

    def on_import_wg(self, instance):
        box = MDBoxLayout(orientation='vertical', adaptive_height=True, spacing=dp(15), padding=dp(20)); btn_file = Button(text="Select .conf File"); btn_paste = Button(text="Paste .conf Content"); box.add_widget(btn_file); box.add_widget(btn_paste)
        popup = Popup(title="Import WireGuard Config", content=box, size_hint=(0.9, None))
        box.bind(minimum_height=lambda inst, h: setattr(popup, 'height', h + dp(70)))
        def dismiss_and_action(action, *args): popup.dismiss(); action(*args)
        btn_file.bind(on_press=lambda *args: dismiss_and_action(self._show_wg_file_chooser))
        btn_paste.bind(on_press=lambda *args: dismiss_and_action(self._show_wg_paste_box)); popup.open()

    def _show_wg_file_chooser(self):
        chooser = FileChooserListView(path=os.path.expanduser("~")); popup_box = BoxLayout(orientation="vertical"); popup_box.add_widget(chooser); btn_row = BoxLayout(size_hint_y=None, height=scale_size(44)); btn_select = Button(text="Select"); btn_row.add_widget(btn_select); popup_box.add_widget(btn_row); popup = Popup(title="Select .conf File", content=popup_box, size_hint=(0.9, 0.9))
        def do_select(*a):
            if not chooser.selection: return small_popup("Error", "No file selected.")
            try:
                with open(chooser.selection[0], "r", encoding="utf-8") as f: txt = f.read()
                popup.dismiss(); self._parse_and_populate_wg_form(txt)
            except Exception as e: small_popup("Error", f"Failed to read file: {e}")
        btn_select.bind(on_press=do_select); popup.open()

    def _show_wg_paste_box(self):
        theme = THEMES.get(current_theme, THEMES["Default"]); box = MDBoxLayout(orientation='vertical', md_bg_color=theme['bg']); ti = TextInput(hint_text='Paste full .conf content here', multiline=True, size_hint=(1,1)); recolor_widget_recursively(ti, theme); box.add_widget(ti); row = MDBoxLayout(size_hint_y=None, height=scale_size(44), adaptive_height=True); b_ok = Button(text='Import'); b_cancel = Button(text='Cancel'); recolor_widget_recursively(b_ok, theme); recolor_widget_recursively(b_cancel, theme); row.add_widget(b_ok); row.add_widget(b_cancel); box.add_widget(row); p = Popup(title='Paste WireGuard .conf', content=box, size_hint=(0.95,0.95))
        def _do_import(*aa):
            txt = ti.text or ''; p.dismiss()
            if not txt.strip(): return small_popup('Error','Nothing pasted.')
            self._parse_and_populate_wg_form(txt)
        b_ok.bind(on_press=_do_import); b_cancel.bind(on_press=p.dismiss); p.open()
    
    def _parse_and_populate_wg_form(self, text):
        self.set_proxy_type("WireGuard")
        wg = parse_wireguard_conf(text); self.wg_server.text, self.wg_port.text, self.wg_private_key.text, self.wg_local_address.text, self.wg_peer_public_key.text = wg.get("server", ""), str(wg.get("server_port", "")), wg.get("private_key", ""), ",".join(wg.get("local_address", [])), wg.get("peer_public_key", ""); small_popup("Parsed", "WireGuard config parsed. Review and click 'Add To Proxy List'.")

    def toggle_dns(self, instance): self.dns_protection_on = not self.dns_protection_on; self.dns_toggle_btn.text = "ON" if self.dns_protection_on else "OFF"
    def generate_config(self, instance):
        if not self.added_proxies: return small_popup("Error", "Proxy list is empty. Please add a proxy first.")
        outbounds = [{"type":"direct","tag":"direct"}]; tags = []
        selected_proxies = [p for p in self.added_proxies if p.selected]
        if not selected_proxies: return small_popup("Error", "No proxies are selected in the Proxy List.")
        for p in selected_proxies:
            ob = _outbound_from_added(outbound_tag_for_type, p)
            if ob: outbounds.append(ob); tags.append(ob["tag"])
        final_tag = "PROXY" if len(tags) > 1 else (tags[0] if tags else "direct")
        if len(tags) > 1: outbounds.append({"type": "selector", "tag": "PROXY", "outbounds": tags + ["direct"]})
        outbounds.append({"type": "selector", "tag": "dns-out", "outbounds": tags + ["direct"]})
        dns_detour = final_tag if self.dns_protection_on and tags else "dns-out"
        config = {"log":{"level":"error"}, "dns":{"servers":[{"address":"https://1.1.1.1/dns-query","detour":dns_detour}]}, "inbounds":[{"type":"tproxy","listen":"::","listen_port":9898,"sniff":True}], "outbounds":outbounds, "route":{"final":final_tag}, "experimental": {"clash_api": {"external_controller": "0.0.0.0:9090", "external_ui": "dashboard"}}}
        self.generated_config = json.dumps(config, indent=2); small_popup("Generated", f"Config created with {len(tags)} proxy(s).\nUse 'View' or 'Copy' to access it.")
    def view_config(self, instance): small_popup("Generated Config", self.generated_config if self.generated_config else "Nothing generated yet.", height=0.8)
    def copy_config(self, instance):
        if not self.generated_config: return small_popup("Error", "No config to copy.")
        Clipboard.copy(self.generated_config); small_popup("Copied", "Config copied to clipboard.")
    def save_config(self, instance):
        if not self.generated_config: return small_popup("Error", "No config to save.")
        chooser = FileChooserListView(path=os.path.expanduser("~")); popup_box = BoxLayout(orientation="vertical"); popup_box.add_widget(chooser); btn_row = BoxLayout(size_hint_y=None, height=scale_size(44)); btn_save = Button(text="Save Here"); btn_cancel = Button(text="Cancel"); btn_row.add_widget(btn_save); btn_row.add_widget(btn_cancel); popup_box.add_widget(btn_row); popup = Popup(title="Save Config File", content=popup_box, size_hint=(0.9, 0.9))
        def do_save(*a):
            path = chooser.selection[0] if chooser.selection else os.path.join(chooser.path, "box_config.json")
            if os.path.isdir(path): path = os.path.join(path, "box_config.json")
            try:
                with open(path, "w", encoding="utf-8") as f: f.write(self.generated_config)
                popup.dismiss(); small_popup("Saved", f"Saved to {path}")
            except Exception as e: small_popup("Error", f"Failed to save: {e}")
        btn_save.bind(on_press=do_save); btn_cancel.bind(on_press=popup.dismiss); popup.open()
    def add_current_proxy(self, ptype: str):
        ptype = (ptype or "").lower(); label = ptype.upper(); data = {}; raw = ""
        if ptype == "wireguard":
            if not (self.wg_private_key.text.strip() and self.wg_server.text.strip()): return small_popup("Error", "Fill WireGuard details first.")
            data = {"private_key": self.wg_private_key.text.strip(), "server": self.wg_server.text.strip(), "server_port": int(self.wg_port.text.strip() or 51820), "peer_public_key": self.wg_peer_public_key.text.strip(), "local_address": self.wg_local_address.text.strip()}; label = f"WG {data['server']}:{data['server_port']}"
        elif ptype == "socks5":
            if not (self.proxy_host.text.strip() and self.proxy_port.text.strip()): return small_popup("Error", "Fill SOCKS5 details first.")
            data = {"server": self.proxy_host.text.strip(), "server_port": int(self.proxy_port.text.strip() or 0), "username": self.proxy_user.text.strip(), "password": self.proxy_pass.text.strip()}; label = f"SOCKS5 {data['server']}:{data['server_port']}"
        elif ptype in ("vmess","vless","shadowsocks"):
            raw = (self.paste_input.text or "").strip()
            if not raw: return small_popup("Error", f"Paste a {ptype} link first.")
            label = f"{ptype.upper()} (from paste)"
        else: return small_popup("Unknown", f"Unsupported type: {ptype}")
        self.added_proxies.append(AddedProxy(ptype, label, data, raw)); self.refresh_added_list(); small_popup("Added", f"{label} added to list."); self.nav_panel.switch_tab('proxy_list')
    def refresh_added_list(self):
        self.proxies_list.clear_widgets()
        for idx, p in enumerate(self.added_proxies):
            card = MDCard(orientation='vertical', size_hint_y=None, adaptive_height=True, padding=8)
            row = MDBoxLayout(adaptive_height=True, spacing=5)
            cb = CheckBox(active=p.selected, size_hint_x=None, width=scale_size(48)); cb.bind(active=lambda inst, val, i=idx: setattr(self.added_proxies[i], 'selected', val)); row.add_widget(cb)
            row.add_widget(Label(text=p.label, shorten=True, shorten_from='right', halign="left"))
            btn_edit = Button(text="Edit", size_hint_x=None, width=scale_size(90)); btn_edit.bind(on_press=lambda *a, i=idx: self.edit_proxy(i)); row.add_widget(btn_edit)
            btn_check = Button(text="Check", size_hint_x=None, width=scale_size(90)); btn_check.bind(on_press=lambda *a, i=idx: self.check_single_proxy(i)); row.add_widget(btn_check)
            btn_rm = Button(text="X", size_hint_x=None, width=scale_size(50)); btn_rm.bind(on_press=lambda *a, i=idx: self._remove_added(i)); row.add_widget(btn_rm)
            card.add_widget(row); self.proxies_list.add_widget(card)
    def _remove_added(self, i): self.added_proxies.pop(i); self.refresh_added_list()
    def edit_proxy(self, index):
        proxy_to_edit = self.added_proxies[index]; theme = THEMES.get(current_theme, THEMES["Default"])
        content = MDBoxLayout(orientation='vertical', spacing=10, padding=10, adaptive_height=True)
        edit_text_input = TextInput(multiline=True, size_hint_y=None); edit_text_input.height = Window.height * 0.4
        recolor_widget_recursively(edit_text_input, theme)
        data_to_show = proxy_to_edit.data if proxy_to_edit.data else {"raw_link": proxy_to_edit.raw}
        edit_text_input.text = json.dumps(data_to_show, indent=2); content.add_widget(edit_text_input)
        button_box = MDBoxLayout(size_hint_y=None, adaptive_height=True, spacing=10)
        btn_save = Button(text="Save Changes"); btn_copy = Button(text="Copy JSON"); button_box.add_widget(btn_save); button_box.add_widget(btn_copy); content.add_widget(button_box)
        popup = Popup(title=f"Edit {proxy_to_edit.label}", content=content, size_hint=(0.9, 0.8))
        def save_changes(*a):
            try:
                new_data = json.loads(edit_text_input.text)
                if "raw_link" in new_data: proxy_to_edit.raw = new_data["raw_link"]; proxy_to_edit.data = {}
                else:
                    proxy_to_edit.data = new_data
                    if proxy_to_edit.ptype == 'wireguard': proxy_to_edit.label = f"WG {new_data.get('server')}:{new_data.get('server_port')}"
                    elif proxy_to_edit.ptype == 'socks5': proxy_to_edit.label = f"SOCKS5 {new_data.get('server')}:{new_data.get('server_port')}"
                self.refresh_added_list(); popup.dismiss()
            except json.JSONDecodeError: small_popup("Error", "Invalid JSON format. Please check your syntax.")
            except Exception as e: small_popup("Error", f"Could not save changes: {e}")
        btn_save.bind(on_press=save_changes); btn_copy.bind(on_press=lambda *a: Clipboard.copy(edit_text_input.text)); popup.open()
    def check_single_proxy(self, idx: int):
        p = self.added_proxies[idx]; host, port = "", 0
        if p.ptype == "wireguard": host, port = p.data.get("server",""), int(p.data.get("server_port") or 51820)
        elif p.ptype == "socks5": host, port = p.data.get("server",""), int(p.data.get("server_port") or 0)
        elif p.ptype == "vmess": d = _decode_vmess(p.raw); host, port = d.get("server",""), int(d.get("server_port") or 0)
        else: host, port = "N/A", 0
        if not host: return small_popup("Error", "Could not determine host to check.")
        def worker():
            ping_func = _icmp_ping_host if p.ptype == 'wireguard' else _tcp_ping_host
            ping_args = (host,) if p.ptype == 'wireguard' else (host, port)
            ok, result = ping_func(*ping_args)
            if not ok: message = f"{p.label}\nStatus: Unreachable\nReason: {result}"; Clock.schedule_once(lambda dt: small_popup("Proxy Check Failed", message)); return
            resolved_ip = result if p.ptype != 'wireguard' else host
            geo_info = "Could not fetch GeoIP data."
            try:
                r = requests.get(f"http://ip-api.com/json/{resolved_ip}?fields=status,country,city,isp,query", timeout=6); data = r.json()
                if data.get("status") == "success": geo_info = (f"Country: {data.get('country', 'N/A')}\nCity: {data.get('city', 'N/A')}\nISP: {data.get('isp', 'N/A')}")
            except Exception: pass
            message = (f"{p.label}\nStatus: Reachable\nHost: {host}\nResolved IP: {resolved_ip}\n------------------\n{geo_info}")
            Clock.schedule_once(lambda dt: small_popup("Proxy Check Result", message))
        threading.Thread(target=worker, daemon=True).start()

    def get_save_path(self):
        return os.path.join(self.app.user_data_dir, "app_data.json")

    def save_state(self, *args, **kwargs):
        # <<< FIX: Now accepts extra arguments to prevent crash on exit >>>
        try:
            state = {"theme": current_theme, "dns_protection_on": self.dns_protection_on, "proxies": [asdict(p) for p in self.added_proxies]}
            with open(self.get_save_path(), 'w') as f: json.dump(state, f, indent=2)
            print("App state saved.")
        except Exception as e:
            print(f"Failed to save state: {e}")

    def load_state(self, *args):
        path = self.get_save_path()
        if not os.path.exists(path): return
        try:
            with open(path, 'r') as f: state = json.load(f)
            apply_theme(state.get("theme", "Default"), self.app)
            self.theme_button.text = state.get("theme", "Default")
            self.dns_protection_on = state.get("dns_protection_on", False)
            self.dns_toggle_btn.text = "ON" if self.dns_protection_on else "OFF"
            self.added_proxies = [AddedProxy(**p_data) for p_data in state.get("proxies", [])]
            self.refresh_added_list()
            print("App state loaded.")
        except Exception as e:
            print(f"Failed to load state: {e}")

class SingboxApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"; self.theme_cls.primary_palette = "Blue"
        main_layout = MDBoxLayout(orientation='vertical')
        toolbar = MDTopAppBar(title="Sing-Box Configurator")
        toolbar.right_action_items = [["information-outline", lambda x: self.show_info()]]
        main_layout.add_widget(toolbar)
        self.main_ui = MainUI()
        main_layout.add_widget(self.main_ui)
        Clock.schedule_once(lambda dt: apply_theme(current_theme, self), 0.1)
        return main_layout
    def show_info(self):
        theme = THEMES.get(current_theme, THEMES["Default"]); content = MDBoxLayout(orientation="vertical", spacing=dp(15), padding=dp(20), adaptive_height=True)
        content.add_widget(Label(text="Sing-Box Configurator v1.0", font_style="H6", adaptive_height=True))
        content.add_widget(Label(text="App data and proxies are saved automatically on exit.", adaptive_height=True, font_style="Caption"))
        content.add_widget(Label(text="Developed with Love, August 2025.", adaptive_height=True))
        btn_contact = Button(text="Contact Sir10Ma on Telegram"); btn_contact.bind(on_release=lambda x: webbrowser.open("https://t.me/Sir10MA")); content.add_widget(btn_contact)
        popup = Popup(title="About", content=content, size_hint=(0.9, None))
        content.bind(minimum_height=lambda inst, h: setattr(popup, 'height', h + dp(70)))
        recolor_widget_recursively(popup.content, theme); popup.open()

if __name__ == '__main__':
    SingboxApp().run()
