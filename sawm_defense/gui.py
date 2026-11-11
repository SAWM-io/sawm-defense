"""Native desktop console for the same service used by the CLI.

The UI never treats observation text as an instruction. All privileged decisions
remain in AgentService and its local executor. Network, scan and journal calls
run in workers; Tk widgets are only touched by the main thread.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
import json
from pathlib import Path
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable


BG = "#111214"
PANEL = "#1b1c1f"
CARD = "#222327"
FIELD = "#151618"
EDGE = "#3b3d42"
TEXT = "#f2f2f3"
MUTED = "#afb1b7"
SOFT = "#73767e"


def _display(value: Any, limit: int = 18000) -> str:
    if isinstance(value, (dict, list, tuple)):
        result = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    elif value is None:
        result = "Non renseigné"
    else:
        result = str(value)
    # The text is displayed, never interpreted as a command or markup.
    return result[:limit] + ("\n[… affichage abrégé]" if len(result) > limit else "")


def _clock(value: Any) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%d/%m %H:%M:%S")
    except (ValueError, TypeError, OverflowError):
        return str(value or "—")[:24]


def _number(value: Any, suffix: str = "") -> str:
    try:
        return f"{float(value):.1f}{suffix}"
    except (TypeError, ValueError):
        return "n.d."


def _lines(value: str) -> list[str]:
    return list(dict.fromkeys(line.strip() for line in value.splitlines() if line.strip()))


class DefenseApp:
    """Tk frontend. A service factory can be injected for isolated GUI tests."""

    def __init__(self, root: tk.Tk, state_dir: str | Path | None = None,
                 service_factory: Callable[..., Any] | None = None):
        self.root = root
        self.state_dir = state_dir
        self._service_factory = service_factory
        self.service: Any = None
        self._created_service: Any = None
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._results: queue.Queue = queue.Queue()
        self._inflight: dict[str, str] = {}
        self._closing = False
        self._poll_timer: str | None = None
        self._status: dict = {}
        self._event_rows: dict[str, dict] = {}
        self._action_rows: dict[str, dict] = {}
        self._notification_rows: dict[str, dict] = {}
        self._order_rows: dict[str, dict] = {}
        self._launch_checked = False
        self._history: deque = deque(maxlen=100)
        self._last_sample: str | None = None
        self._settings_loaded = False
        self._chat_pending = False
        self._vars: dict[str, tk.Variable] = {}
        self._style()
        root.title("SAWM Defense — Protection & activité")
        root.geometry("1280x870")
        root.minsize(980, 660)
        root.configure(background=BG)
        root.protocol("WM_DELETE_WINDOW", self._close)
        if sys.platform == "darwin":
            # The native macOS app menu bypasses WM_DELETE_WINDOW by default.
            root.createcommand("::tk::mac::Quit", self._close)
        self._build()
        root.after(80, self._drain)
        self._submit("initialize", "Ouverture du journal local", self._create_service, self._initialized)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        font = "SF Pro Text" if sys.platform == "darwin" else "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
        self.font = font
        self.root.option_add("*Font", (font, 11))
        style.configure(".", background=BG, foreground=TEXT, bordercolor=EDGE,
                        lightcolor=EDGE, darkcolor=EDGE, troughcolor=FIELD, font=(font, 11))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("Card.TFrame", background=CARD)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Panel.TLabel", background=PANEL)
        style.configure("Card.TLabel", background=CARD)
        style.configure("CardMuted.TLabel", background=CARD, foreground=MUTED, font=(font, 10))
        style.configure("Value.TLabel", background=CARD, font=(font, 20, "bold"))
        style.configure("Title.TLabel", font=(font, 25, "bold"))
        style.configure("Section.TLabel", font=(font, 14, "bold"))
        style.configure("TButton", background=CARD, foreground=TEXT, padding=(13, 9), borderwidth=1, focusthickness=1)
        style.map("TButton", background=[("active", EDGE), ("disabled", PANEL)], foreground=[("disabled", SOFT)])
        style.configure("Primary.TButton", background=TEXT, foreground=BG, font=(font, 11, "bold"))
        style.map("Primary.TButton", background=[("active", "#d4d4d7"), ("disabled", EDGE)], foreground=[("disabled", SOFT)])
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 10, 0, 10))
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(12, 11))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT)])
        style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT, padding=7, insertcolor=TEXT)
        style.configure("TSpinbox", fieldbackground=FIELD, foreground=TEXT, arrowcolor=TEXT, padding=6)
        style.configure("TCombobox", fieldbackground=FIELD, foreground=TEXT, arrowcolor=TEXT, padding=6)
        style.map("TCombobox", fieldbackground=[("readonly", FIELD)], foreground=[("readonly", TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", FIELD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", EDGE)
        style.configure("TCheckbutton", background=BG, foreground=TEXT, padding=5)
        style.map("TCheckbutton", background=[("active", BG)], indicatorcolor=[("selected", TEXT), ("!selected", EDGE)])
        style.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT,
                        rowheight=31, borderwidth=0, font=(font, 10))
        style.configure("Treeview.Heading", background=CARD, foreground=TEXT, padding=(8, 9), font=(font, 10, "bold"))
        style.map("Treeview", background=[("selected", EDGE)], foreground=[("selected", "white")])
        style.configure("TLabelframe", background=BG, bordercolor=EDGE, borderwidth=1)
        style.configure("TLabelframe.Label", background=BG, foreground=TEXT, font=(font, 12, "bold"))
        style.configure("TPanedwindow", background=BG)

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        header = ttk.Frame(self.root, padding=(25, 19, 25, 5))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        emblem = tk.Canvas(header, width=49, height=49, background=BG, highlightthickness=0)
        emblem.grid(row=0, column=0, rowspan=2, padx=(0, 13))
        logo_path = Path(__file__).parent / "assets/sawm-basira.png"
        if logo_path.is_file():
            self._brand_logo = tk.PhotoImage(file=str(logo_path))
            factor = max(1, round(max(self._brand_logo.width(), self._brand_logo.height()) / 49))
            self._brand_logo = self._brand_logo.subsample(factor)
            emblem.create_image(24, 24, image=self._brand_logo)
        else:
            emblem.create_oval(5, 5, 43, 43, outline=MUTED, width=2)
            emblem.create_oval(18, 18, 30, 30, fill=TEXT, outline=TEXT)
        ttk.Label(header, text="SAWM DEFENSE", style="Title.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(header, text="BASIRA CLOUD  /  Votre poste, votre mémoire, vos autorisations", style="Muted.TLabel").grid(row=1, column=1, sticky="w", pady=(4, 0))
        self.header_state = ttk.Label(header, text="INITIALISATION", style="Muted.TLabel")
        self.header_state.grid(row=0, column=2, sticky="e")
        ttk.Label(header, text="Console locale · actions traçables", style="Muted.TLabel").grid(row=1, column=2, sticky="e")
        content = ttk.Frame(self.root, padding=(25, 0, 25, 0))
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        self.tabs = ttk.Notebook(content)
        self.tabs.grid(row=0, column=0, sticky="nsew")
        self.pages: dict[str, ttk.Frame] = {}
        for key, title in [("overview", "Vue d’ensemble"), ("events", "Observations"),
                           ("system", "Système"), ("autonomy", "Veille & missions"), ("chat", "Parler à SAWM"),
                           ("settings", "Réglages"), ("journal", "Journal")]:
            page = ttk.Frame(self.tabs, padding=(0, 10, 0, 0))
            self.tabs.add(page, text=title)
            self.pages[key] = page
        self._overview()
        self._observations()
        self._system()
        self._autonomy()
        self._chat()
        self._settings()
        self._journal()
        footer = ttk.Frame(self.root, padding=(25, 12, 25, 12))
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self.status_text = ttk.Label(footer, text="Chargement…", style="Muted.TLabel")
        self.status_text.grid(row=0, column=0, sticky="w")
        self.last_update = ttk.Label(footer, text="", style="Muted.TLabel")
        self.last_update.grid(row=0, column=1, sticky="e")

    def _overview(self) -> None:
        page = self.pages["overview"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)
        tools = ttk.Frame(page)
        tools.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.monitor_button = ttk.Button(tools, text="Démarrer la surveillance", style="Primary.TButton", command=self._toggle_monitor)
        self.monitor_button.pack(side="left")
        ttk.Button(tools, text="Analyser un fichier", command=self._scan).pack(side="left", padx=8)
        ttk.Button(tools, text="Rapport d’activité ↗", command=self._export).pack(side="right")
        cards = ttk.Frame(page)
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        self.cards: dict[str, tuple[ttk.Label, ttk.Label]] = {}
        for index, (name, title) in enumerate([("monitor", "SURVEILLANCE"), ("cloud", "SAWM + BASIRA"), ("av", "ANTIVIRUS LOCAL"), ("actions", "AUTOMATISATION")]):
            cards.columnconfigure(index, weight=1, uniform="cards")
            card = ttk.Frame(cards, padding=(15, 14), style="Card.TFrame")
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 5, 0 if index == 3 else 5))
            ttk.Label(card, text=title, style="CardMuted.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="—", style="Value.TLabel")
            value.pack(anchor="w", pady=(10, 5))
            detail = ttk.Label(card, text="En attente des mesures", style="CardMuted.TLabel", wraplength=230)
            detail.pack(anchor="w")
            self.cards[name] = (value, detail)
        pane = ttk.Panedwindow(page, orient="horizontal")
        pane.grid(row=2, column=0, sticky="nsew")
        left = ttk.Frame(pane, style="Panel.TFrame", padding=15)
        right = ttk.Frame(pane, style="Panel.TFrame", padding=15)
        pane.add(left, weight=3)
        pane.add(right, weight=2)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=2)
        left.rowconfigure(3, weight=2)
        ttk.Label(left, text="Activité de la machine", style="Panel.TLabel", font=(self.font, 14, "bold")).grid(row=0, column=0, sticky="w")
        self.chart = tk.Canvas(left, background=PANEL, highlightthickness=0, height=180)
        self.chart.grid(row=1, column=0, sticky="nsew", pady=10)
        self.chart.bind("<Configure>", lambda event: self._draw_chart())
        ttk.Label(left, text="Dernières observations", style="Panel.TLabel", font=(self.font, 12, "bold")).grid(row=2, column=0, sticky="w", pady=(9, 8))
        self.recent_text = self._text(left, height=7)
        self.recent_text.grid(row=3, column=0, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)
        ttk.Label(right, text="Couverture effective", style="Panel.TLabel", font=(self.font, 14, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(right, text="Les droits du compte et les outils installés\ndéterminent ce qui peut être contrôlé.", style="Panel.TLabel", foreground=MUTED).grid(row=1, column=0, sticky="w", pady=(9, 13))
        self.coverage_text = self._text(right, height=12)
        self.coverage_text.grid(row=2, column=0, sticky="nsew")
        ttk.Button(right, text="Configurer la protection →", command=lambda: self.tabs.select(self.pages["settings"])).grid(row=3, column=0, sticky="ew", pady=(12, 0))

    def _tree(self, parent: Any, columns: list[tuple[str, str, int]], height: int = 8) -> tuple[ttk.Frame, ttk.Treeview]:
        frame = ttk.Frame(parent)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height, selectmode="browse")
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=60, stretch=key in {"summary", "name", "reason", "remote", "detail"})
        tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        hscroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        hscroll.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=scrollbar.set, xscrollcommand=hscroll.set)
        return frame, tree

    def _observations(self) -> None:
        page = self.pages["events"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        tools = ttk.Frame(page)
        tools.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(tools, text="Événements observés", style="Section.TLabel").pack(side="left")
        self.event_filter = tk.StringVar(value="Tous")
        cb = ttk.Combobox(tools, textvariable=self.event_filter, values=["Tous", "Alertes", "Fichiers", "Réseau", "Ressources"], state="readonly", width=14)
        cb.pack(side="right")
        cb.bind("<<ComboboxSelected>>", lambda event: self._render_events())
        pane = ttk.Panedwindow(page, orient="vertical")
        pane.grid(row=1, column=0, sticky="nsew")
        frame, self.event_tree = self._tree(pane, [("time", "Heure locale", 145), ("severity", "Niveau", 90), ("kind", "Type", 170), ("summary", "Observation", 500)], 9)
        pane.add(frame, weight=3)
        self.event_tree.bind("<<TreeviewSelect>>", self._show_event)
        detail = ttk.Frame(pane, padding=(0, 12, 0, 0))
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(1, weight=1)
        pane.add(detail, weight=2)
        buttons = ttk.Frame(detail)
        buttons.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(buttons, text="Demander l’analyse à SAWM", command=self._analyze_event).pack(side="left")
        ttk.Label(buttons, text="Action manuelle :", style="Muted.TLabel").pack(side="left", padx=(18, 7))
        self.manual_action = tk.StringVar(value="Mettre en quarantaine")
        ttk.Combobox(buttons, textvariable=self.manual_action, state="readonly", width=23, values=["Mettre en quarantaine", "Arrêter le processus", "Bloquer l’IP autorisée"]).pack(side="left")
        ttk.Button(buttons, text="Examiner et autoriser…", command=self._act).pack(side="left", padx=8)
        self.event_detail = self._text(detail, height=7)
        self.event_detail.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.event_detail, "Sélectionnez une observation pour voir les preuves et leur identifiant.")

    def _system(self) -> None:
        page = self.pages["system"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)
        bar = ttk.Frame(page)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(bar, text="Processus & connexions", style="Section.TLabel").pack(side="left")
        ttk.Button(bar, text="Inventorier les logiciels installés", command=self._inventory).pack(side="right")
        self.system_note = ttk.Label(page, text="Échantillons bornés, selon les droits disponibles. Une connexion inhabituelle n’est pas une preuve de malware.", style="Muted.TLabel", wraplength=1050)
        self.system_note.grid(row=1, column=0, sticky="w", pady=(0, 10))
        pane = ttk.Panedwindow(page, orient="vertical")
        pane.grid(row=2, column=0, sticky="nsew")
        processes, self.process_tree = self._tree(pane, [("pid", "PID", 75), ("name", "Processus", 250), ("user", "Utilisateur", 200), ("detail", "Exécutable", 500)], 8)
        connections, self.connection_tree = self._tree(pane, [("pid", "PID", 75), ("local", "Adresse locale", 260), ("remote", "Adresse distante", 370), ("state", "État", 140)], 8)
        pane.add(processes, weight=1)
        pane.add(connections, weight=1)

    def _autonomy(self) -> None:
        page = self.pages["autonomy"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)
        ttk.Label(page, text="Une veille continue, des missions suivies", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.autonomy_note = ttk.Label(page, text="Chargement de la veille…", style="Muted.TLabel", wraplength=1100)
        self.autonomy_note.grid(row=1, column=0, sticky="w", pady=(9, 12))
        pane = ttk.Panedwindow(page, orient="vertical")
        pane.grid(row=2, column=0, sticky="nsew")
        alerts = ttk.Frame(pane)
        alerts.columnconfigure(0, weight=1)
        alerts.rowconfigure(1, weight=1)
        bar = ttk.Frame(alerts)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.notification_note = ttk.Label(bar, text="Notifications", style="Section.TLabel")
        self.notification_note.pack(side="left")
        ttk.Button(bar, text="Marquer comme lue", command=self._acknowledge_notification).pack(side="right")
        frame, self.notification_tree = self._tree(alerts, [("time", "Heure", 130), ("severity", "Niveau", 80), ("read", "Lecture", 95), ("delivery", "Notification système", 160), ("summary", "Observation", 510)], 7)
        frame.grid(row=1, column=0, sticky="nsew")
        self.notification_tree.bind("<Double-1>", self._show_notification)
        pane.add(alerts, weight=1)
        missions = ttk.Frame(pane, padding=(0, 12, 0, 0))
        missions.columnconfigure(0, weight=1)
        missions.rowconfigure(2, weight=1)
        bar = ttk.Frame(missions)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(bar, text="Confier une mission", style="Section.TLabel").pack(side="left", padx=(0, 12))
        self.mission_kind = tk.StringVar(value="Inventorier les logiciels")
        ttk.Combobox(bar, textvariable=self.mission_kind, state="readonly", width=29, values=["Inventorier les logiciels", "Analyser un fichier", "Analyser une observation", "Produire un rapport"]).pack(side="left")
        ttk.Button(bar, text="Confier →", style="Primary.TButton", command=self._submit_mission).pack(side="left", padx=8)
        ttk.Button(bar, text="Voir le résultat", command=self._show_order).pack(side="right")
        ttk.Label(missions, text="Les missions sont persistantes. Une observation s’analyse depuis sa sélection dans Observations. Les interventions restent contrôlées par vos autorisations locales.", style="Muted.TLabel", wraplength=1060).grid(row=1, column=0, sticky="w", pady=(0, 8))
        frame, self.order_tree = self._tree(missions, [("time", "Demandée à", 130), ("kind", "Mission", 120), ("status", "État", 140), ("actor", "Demandée par", 170), ("detail", "Cible / résultat", 430)], 7)
        frame.grid(row=2, column=0, sticky="nsew")
        self.order_tree.bind("<Double-1>", self._show_order)
        pane.add(missions, weight=1)

    def _chat(self) -> None:
        page = self.pages["chat"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        ttk.Label(page, text="Demandez une explication, un bilan ou une analyse à votre agent.", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.chat_history = self._text(page, height=20)
        self.chat_history.grid(row=1, column=0, sticky="nsew")
        self._set_text(self.chat_history, "SAWM / ESPACE DE DIALOGUE\n\nConfigurez vos accès Cloud dans Réglages, puis vérifiez la connexion.\nVos questions et les observations sélectionnées par le service sont envoyées à votre espace Basira. Les réponses expliquent les observations. Confiez une tâche dans Veille & missions ; les permissions d’action restent contrôlées localement.\n")
        ttk.Label(page, text="Ctrl + Entrée pour envoyer · Une réponse de SAWM ne constitue pas une autorisation supplémentaire.", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 6))
        composer = ttk.Frame(page)
        composer.grid(row=3, column=0, sticky="ew")
        composer.columnconfigure(0, weight=1)
        self.chat_input = self._text(composer, height=3, readonly=False)
        self.chat_input.grid(row=0, column=0, sticky="ew")
        self.chat_input.bind("<Control-Return>", self._send_chat)
        self.chat_input.bind("<Command-Return>", self._send_chat)
        self.chat_send = ttk.Button(composer, text="Envoyer →", style="Primary.TButton", command=self._send_chat)
        self.chat_send.grid(row=0, column=1, sticky="ns", padx=(10, 0))

    def _settings(self) -> None:
        page = self.pages["settings"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        buttons = ttk.Frame(page)
        buttons.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(buttons, text="Un accès Cloud, des périmètres explicites", style="Section.TLabel").pack(side="left")
        ttk.Button(buttons, text="Enregistrer", style="Primary.TButton", command=self._save_settings).pack(side="right")
        ttk.Button(buttons, text="Vérifier l’accès Cloud", command=lambda: self._save_settings(check=True)).pack(side="right", padx=8)
        scroll = tk.Canvas(page, background=BG, highlightthickness=0)
        scroll.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(page, orient="vertical", command=scroll.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        scroll.configure(yscrollcommand=scrollbar.set)
        body = ttk.Frame(scroll)
        item = scroll.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda event: scroll.configure(scrollregion=scroll.bbox("all")))
        scroll.bind("<Configure>", lambda event: scroll.itemconfigure(item, width=event.width))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        api = ttk.LabelFrame(body, text="01  SAWM & Basira Cloud", padding=15)
        api.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 13))
        api.columnconfigure(1, weight=1)
        self._vars["cloud_enabled"] = tk.BooleanVar(value=False)
        self._vars["cloud_upload_enabled"] = tk.BooleanVar(value=False)
        ttk.Checkbutton(api, text="Activer l’analyse et le dialogue Cloud", variable=self._vars["cloud_enabled"]).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(api, text="Synchroniser les métadonnées d’événements vers Basira (noms, chemins, adresses)", variable=self._vars["cloud_upload_enabled"]).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 9))
        for index, (key, label, initial) in enumerate([("cloud_base_url", "URL API", "https://basira-api.sawm.io/api/v1/basira"), ("space_id", "Identifiant d’espace", ""), ("entity_id", "Identifiant de mémoire", ""), ("api_key", "Clé API", "")], start=2):
            ttk.Label(api, text=label).grid(row=index, column=0, sticky="w", padx=(0, 15), pady=5)
            var = tk.StringVar(value=initial)
            self._vars[key] = var
            ttk.Entry(api, textvariable=var, show="•" if key == "api_key" else "").grid(row=index, column=1, sticky="ew", pady=5)
        self._vars["persist_key"] = tk.BooleanVar(value=True)
        ttk.Checkbutton(api, text="Conserver la clé dans le trousseau sécurisé du système", variable=self._vars["persist_key"]).grid(row=6, column=1, sticky="w", pady=(5, 0))
        self.key_note = ttk.Label(api, text="Laissez la clé vide pour conserver la clé déjà configurée. Aucun secret n’est stocké dans les réglages.", style="Muted.TLabel", wraplength=850)
        self.key_note.grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
        scopes = ttk.LabelFrame(body, text="02  Dossiers surveillés", padding=15)
        scopes.grid(row=1, column=0, sticky="nsew", padx=(0, 8), pady=(0, 13))
        scopes.columnconfigure(0, weight=1)
        ttk.Label(scopes, text="Ajoutez les dossiers que l’agent peut observer.\nLes contenus ne sont pas transmis automatiquement.", style="Muted.TLabel", wraplength=370).grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.monitor_paths = tk.Listbox(scopes, background=FIELD, foreground=TEXT, selectbackground=EDGE, borderwidth=0, highlightthickness=1, highlightbackground=EDGE, height=5, exportselection=False)
        self.monitor_paths.grid(row=1, column=0, sticky="ew")
        foldertools = ttk.Frame(scopes)
        foldertools.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(foldertools, text="+ Ajouter un dossier", command=self._add_folder).pack(side="left")
        ttk.Button(foldertools, text="Retirer", command=self._remove_folder).pack(side="left", padx=8)
        automatic = ttk.LabelFrame(body, text="03  Actions automatiques", padding=15)
        automatic.grid(row=1, column=1, sticky="nsew", padx=(8, 0), pady=(0, 13))
        self.auto_vars: dict[str, tk.BooleanVar] = {}
        for key, label in [("quarantine", "Mettre automatiquement en quarantaine"), ("terminate", "Arrêter un exécutable malveillant autorisé"), ("block_ip", "Bloquer une IP selon les preuves autorisées")]:
            var = tk.BooleanVar(value=False)
            self.auto_vars[key] = var
            control = ttk.Checkbutton(automatic, text=label, variable=var)
            control.pack(anchor="w")
        ttk.Label(automatic, text="Une intervention automatique exige une permission et une preuve locale vérifiée : antivirus pour un fichier ou processus, source d’authentification fiable pour une IP. Un arrêt peut perdre le travail en cours ; un blocage peut interrompre un service. Les seules anomalies sont signalées.", style="Muted.TLabel", wraplength=390).pack(anchor="w", pady=(10, 0))
        restrictions = ttk.LabelFrame(body, text="04  Périmètre des interventions", padding=15)
        restrictions.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 13))
        self.scope_texts: dict[str, tk.Text] = {}
        for index, (key, label) in enumerate([("allowed_process_paths", "Exécutables autorisés à être arrêtés\nChemins complets, un par ligne"), ("allowed_remote_ips", "IP autorisées au blocage\nAdresses publiques exactes, une par ligne"), ("protected_paths", "Chemins protégés\nJamais mis en quarantaine")]):
            restrictions.columnconfigure(index, weight=1, uniform="scopes")
            section = ttk.Frame(restrictions)
            section.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 6, 0 if index == 2 else 6))
            ttk.Label(section, text=label, style="Muted.TLabel", wraplength=270).pack(anchor="w", pady=(0, 7))
            widget = self._text(section, height=4, readonly=False)
            widget.pack(fill="both", expand=True)
            self.scope_texts[key] = widget
        controls = ttk.LabelFrame(body, text="05  Rythme, budget & démarrage", padding=15)
        controls.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        for index, (key, label, value, minimum, maximum) in enumerate([("poll_seconds", "Intervalle local (s)", 5, 1, 3600), ("cloud_per_hour", "Opérations Cloud / heure", 4, 0, 120), ("max_file_mb", "Taille analysable (Mo)", 100, 1, 2048), ("retention_days", "Rétention locale (jours)", 30, 1, 3650)]):
            col = ttk.Frame(controls)
            col.grid(row=0, column=index, sticky="ew", padx=(0, 16))
            controls.columnconfigure(index, weight=1)
            ttk.Label(col, text=label, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
            var = tk.StringVar(value=str(value))
            self._vars[key] = var
            ttk.Spinbox(col, from_=minimum, to=maximum, textvariable=var, width=11).pack(anchor="w")
        startup = ttk.Frame(controls)
        startup.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(16, 0))
        ttk.Button(startup, text="Activer au démarrage de session…", command=lambda: self._startup(True)).pack(side="left")
        ttk.Button(startup, text="Désactiver le démarrage…", command=lambda: self._startup(False)).pack(side="left", padx=8)
        ttk.Label(controls, text="Service utilisateur supervisé. Les autorisations système supplémentaires ne sont jamais accordées silencieusement.", style="Muted.TLabel", wraplength=950).grid(row=2, column=0, columnspan=4, sticky="w", pady=(10, 0))

        autonomy = ttk.LabelFrame(body, text="06  Veille autonome & authentification", padding=15)
        autonomy.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        autonomy.columnconfigure(0, weight=1)
        for index, (key, label, default) in enumerate([
            ("monitor_on_launch", "Démarrer la veille locale à l’ouverture de l’application", True),
            ("protect_downloads", "Surveiller aussi le dossier Téléchargements de cette session", True),
            ("automatic_scan_enabled", "Analyser automatiquement les fichiers nouveaux ou modifiés avec l’antivirus local", True),
            ("notifications_enabled", "Envoyer les alertes au système de notifications du poste", True),
            ("autonomous_analysis_enabled", "Analyser les alertes avec SAWM en arrière-plan (budget Cloud respecté)", True),
            ("auth_journal_enabled", "Lire les événements SSH du journal système Linux, selon les droits disponibles", False),
            ("autoblock_auth_ips", "Autoriser le blocage temporaire des IP publiques attribuées à des échecs répétés", False),
        ]):
            self._vars[key] = tk.BooleanVar(value=default)
            ttk.Checkbutton(autonomy, text=label, variable=self._vars[key]).grid(row=index, column=0, columnspan=2, sticky="w")
        ttk.Label(autonomy, text="Le blocage issu du journal exige aussi la permission « Bloquer une IP ». Les IP protégées sont exclues. Les journaux importés manuellement peuvent alerter, mais ne constituent pas une preuve fiable pour bloquer automatiquement.", style="Muted.TLabel", wraplength=1010).grid(row=7, column=0, columnspan=2, sticky="w", pady=(7, 12))
        inputs = ttk.Frame(autonomy)
        inputs.grid(row=8, column=0, columnspan=2, sticky="ew")
        for index, (key, label, value, minimum, maximum) in enumerate([
            ("auth_failure_threshold", "Échecs avant alerte", 5, 3, 100),
            ("auth_window_seconds", "Fenêtre d’observation (s)", 300, 30, 3600),
            ("auto_block_seconds", "Durée du blocage (s)", 600, 60, 3600),
            ("download_scan_settle_seconds", "Stabilité avant analyse (s)", 3, 1, 120),
        ]):
            section = ttk.Frame(inputs)
            section.grid(row=0, column=index, sticky="ew", padx=(0, 20))
            inputs.columnconfigure(index, weight=1)
            ttk.Label(section, text=label, style="Muted.TLabel").pack(anchor="w")
            self._vars[key] = tk.StringVar(value=str(value))
            ttk.Spinbox(section, from_=minimum, to=maximum, textvariable=self._vars[key], width=12).pack(anchor="w", pady=(6, 0))
        for index, (key, label) in enumerate([
            ("auth_log_paths", "Journaux d’authentification à observer · chemins complets, un par ligne"),
            ("protected_remote_ips", "IP à protéger du blocage · adresses exactes, une par ligne"),
        ]):
            ttk.Label(autonomy, text=label, style="Muted.TLabel").grid(row=9+2*index, column=0, columnspan=2, sticky="w", pady=(13, 5))
            widget = self._text(autonomy, height=3, readonly=False)
            widget.grid(row=10+2*index, column=0, columnspan=2, sticky="ew")
            self.scope_texts[key] = widget

        def wheel(event):
            if isinstance(event.widget, (tk.Text, tk.Listbox, ttk.Spinbox)):
                return None
            if getattr(event, "num", None) in (4, 5):
                units = -1 if event.num == 4 else 1
            else:
                delta = getattr(event, "delta", 0)
                units = -int(delta / 120) if abs(delta) >= 120 else -int(delta)
            scroll.yview_scroll(units, "units")
            return "break"

        def bind_children(widget):
            for binding in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                widget.bind(binding, wheel, add="+")
            for child in widget.winfo_children():
                bind_children(child)

        bind_children(body)
        scroll.bind("<MouseWheel>", wheel)

    def _journal(self) -> None:
        page = self.pages["journal"]
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        self.journal_note = ttk.Label(page, text="Intégrité du journal : en attente de vérification", style="Muted.TLabel")
        self.journal_note.grid(row=0, column=0, sticky="w", pady=(0, 10))
        book = ttk.Notebook(page)
        book.grid(row=1, column=0, sticky="nsew")
        actions = ttk.Frame(book)
        actions.columnconfigure(0, weight=1)
        actions.rowconfigure(0, weight=1)
        book.add(actions, text="Actions & résultats")
        frame, self.action_tree = self._tree(actions, [("time", "Heure", 145), ("action", "Action", 160), ("status", "Résultat", 110), ("reason", "Détail", 550)], 11)
        frame.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Frame(actions, padding=(0, 10))
        bar.grid(row=1, column=0, sticky="ew")
        ttk.Button(bar, text="Voir le reçu", command=self._show_action).pack(side="left")
        ttk.Button(bar, text="Restaurer / annuler l’action…", command=self._restore).pack(side="left", padx=8)
        ttk.Button(bar, text="Exporter le rapport", command=self._export).pack(side="right")
        cloud = ttk.Frame(book)
        cloud.columnconfigure(0, weight=1)
        cloud.rowconfigure(1, weight=1)
        book.add(cloud, text="Appels Basira / SAWM Cloud")
        self.call_note = ttk.Label(cloud, text="Aucun appel enregistré", style="Muted.TLabel")
        self.call_note.grid(row=0, column=0, sticky="w", pady=(0, 10))
        frame, self.call_tree = self._tree(cloud, [("time", "Heure", 145), ("name", "Appel", 240), ("status", "Statut", 100), ("latency", "Durée (ms)", 110), ("tokens", "Jetons fournis", 120), ("detail", "Détail", 330)], 12)
        frame.grid(row=1, column=0, sticky="nsew")
        self.call_tree.bind("<Double-1>", self._show_call)

    def _text(self, parent: Any, height: int = 8, readonly: bool = True) -> tk.Text:
        widget = tk.Text(parent, height=height, width=20, wrap="word", background=FIELD,
                         foreground=TEXT, insertbackground=TEXT, selectbackground=EDGE,
                         relief="flat", borderwidth=0, highlightthickness=1, highlightbackground=EDGE,
                         padx=12, pady=11, font=(self.font, 11), spacing1=2, spacing3=5)
        if readonly:
            widget.configure(state="disabled")
        return widget

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        original = str(widget.cget("state"))
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state=original)

    def _create_service(self):
        if self._service_factory is None:
            from .service import AgentService
            service = AgentService(state_dir=self.state_dir)
        else:
            service = self._service_factory(state_dir=self.state_dir)
        # Closing may begin before Tk consumes the initialization result. Retain
        # the service here so shutdown can close it after this worker completes.
        with self._workers_lock:
            self._created_service = service
        return service

    def _initialized(self, service: Any) -> None:
        self.service = service
        self._request_status()
        self._poll_timer = self.root.after(2000, self._poll)

    def _submit(self, key: str, title: str, operation: Callable, success: Callable | None = None,
                show_error: bool = True) -> bool:
        if self._closing or key in self._inflight:
            return False
        if len(self._inflight) >= 8:
            self.status_text.configure(text="Plusieurs tâches sont en cours. Patientez quelques instants.")
            return False
        self._inflight[key] = title
        self._update_busy()

        def work():
            try:
                self._results.put((key, success, operation(), None, show_error))
            except Exception as error:
                # Keep exceptions concise; service/Cloud layer is responsible for
                # redaction. The actual secret entry is removed as an extra guard.
                self._results.put((key, success, None, str(error), show_error))
            finally:
                with self._workers_lock:
                    self._workers.discard(threading.current_thread())

        worker = threading.Thread(target=work, name=f"sawm-ui-{key}", daemon=True)
        with self._workers_lock:
            self._workers.add(worker)
        try:
            worker.start()
        except RuntimeError:
            with self._workers_lock:
                self._workers.discard(worker)
            self._inflight.pop(key, None)
            raise
        return True

    def _drain(self) -> None:
        if self._closing:
            return
        for _ in range(30):
            try:
                key, success, result, error, show_error = self._results.get_nowait()
            except queue.Empty:
                break
            self._inflight.pop(key, None)
            if error is not None:
                entered_key = str(self._vars["api_key"].get())
                safe_error = error.replace(entered_key, "[clé masquée]") if entered_key else error
                self.status_text.configure(text="Opération non terminée : " + safe_error[:150])
                if key == "chat":
                    self._chat_finished()
                    self._append_chat("INFORMATION", "Le message n’a pas abouti. " + safe_error[:1000])
                if show_error:
                    messagebox.showerror("SAWM Defense", safe_error[:2000], parent=self.root)
            elif success is not None:
                try:
                    success(result)
                except Exception as error:
                    self.status_text.configure(text=f"Affichage indisponible : {type(error).__name__}")
            if key != "status" and self.service is not None:
                self._request_status()
        self._update_busy()
        self.root.after(100, self._drain)

    def _update_busy(self) -> None:
        active = [title for key, title in self._inflight.items() if key != "status"]
        if active:
            self.status_text.configure(text="En cours · " + " · ".join(active)[:160])
        elif self.service is not None:
            self.status_text.configure(text="Les observations restent des données. Les autorisations restent locales.")

    def _poll(self) -> None:
        if self._closing:
            return
        self._request_status()
        self._poll_timer = self.root.after(2000, self._poll)

    def _request_status(self) -> None:
        if self.service is not None:
            self._submit("status", "Actualisation", self.service.status, self._apply_status, show_error=False)

    def _apply_status(self, status: dict) -> None:
        self._status = status
        settings = status.get("settings") or {}
        if not self._settings_loaded:
            self._load_settings(settings)
            self._settings_loaded = True
        running = bool(status.get("running"))
        external = bool(status.get("external_monitor"))
        self.header_state.configure(text="SERVICE DE SURVEILLANCE ACTIF" if external else "SURVEILLANCE ACTIVE" if running else "SURVEILLANCE EN PAUSE")
        self.monitor_button.configure(text="Géré par le service utilisateur" if external else "Mettre en pause" if running else "Démarrer la surveillance", state="disabled" if external else "normal")
        npaths = len((status.get("downloads") or {}).get("effective_paths") or settings.get("monitor_paths") or [])
        self.cards["monitor"][0].configure(text="Active" if running else "En pause")
        self.cards["monitor"][1].configure(text=f"{npaths} dossier(s) · intervalle {settings.get('poll_seconds', 5)} s")
        cloud = status.get("cloud") or {}
        cloud_state = "Désactivé" if not cloud.get("enabled") else "À configurer" if not cloud.get("configured") else str(cloud.get("status") or "Configuré")
        self.cards["cloud"][0].configure(text=cloud_state[:22])
        self.cards["cloud"][1].configure(text=(cloud.get("last_error") or "Basira · TSST · ODVL · SAWM")[:120])
        av = status.get("antivirus") or {}
        available = bool(av.get("available", av.get("status") == "available"))
        engine = av.get("engine") or av.get("name") or "Moteur local"
        self.cards["av"][0].configure(text=str(engine)[:18] if available else "Absent")
        self.cards["av"][1].configure(text="Signatures + inspection structurelle" if available else "Inspection structurelle · sans signatures antivirus")
        nactions = len(settings.get("automatic_actions") or [])
        self.cards["actions"][0].configure(text=f"{nactions} permission(s)")
        self.cards["actions"][1].configure(text="Sous contrôle des preuves locales" if nactions else "Observer & signaler uniquement")
        snapshot = status.get("snapshot") or {}
        stamp = snapshot.get("sampled_at")
        if stamp and stamp != self._last_sample:
            self._last_sample = stamp
            self._history.append((snapshot.get("cpu_percent"), snapshot.get("memory_percent")))
            self._draw_chart()
        self.last_update.configure(text="Dernier échantillon : " + (_clock(stamp) if stamp else "en attente"))
        caps = snapshot.get("capabilities") or []
        notes = []
        for item in caps:
            if isinstance(item, dict):
                marker = "●" if item.get("available") else "○"
                notes.append(f"{marker}  {item.get('name', 'Capteur')}\n   {item.get('reason', 'Disponible' if item.get('available') else 'Indisponible')}")
        security = status.get("security_capabilities")
        if security:
            notes.append("CAPTEURS DE SÉCURITÉ\n" + _display(security, 3500))
        coverage = snapshot.get("coverage") or {}
        if coverage:
            notes.append("PÉRIMÈTRE DE CET ÉCHANTILLON\n" + _display(coverage, 2500))
        if not available:
            notes.append("○  Aucun moteur antivirus à signatures disponible\n   L’inspection structurelle continue. Aucun indicateur reconnu ne certifie pas un fichier sain.")
        self._set_text(self.coverage_text, "\n\n".join(notes) or "Démarrez la surveillance pour mesurer la couverture effective.")
        events = status.get("events") or []
        self._set_text(self.recent_text, "\n\n".join(f"{_clock(e.get('timestamp'))}  /  {e.get('severity', 'info')}\n{e.get('summary', e.get('kind', 'Observation'))}" for e in events[:7]) or "Aucune observation enregistrée. Ajoutez un dossier et démarrez la surveillance.")
        self._render_events()
        self._render_system(snapshot)
        self._render_journal(status)
        self._render_autonomy(status)
        if not self._launch_checked:
            self._launch_checked = True
            if settings.get("monitor_on_launch", False) and not running and not external and self.service is not None:
                self._submit("monitor", "Démarrage de la veille locale", self.service.start, lambda result: self._request_status())
        key = status.get("key") or {}
        self.key_note.configure(text=(f"Clé disponible · {key.get('backend', 'stockage sécurisé ou session')} · laissez vide pour la conserver." if key.get("available") else "Aucune clé enregistrée. Stockage dans le trousseau système ou uniquement pour cette session."))

    def _load_settings(self, settings: dict) -> None:
        for key, var in self._vars.items():
            if key in settings:
                var.set(settings[key])
        self.monitor_paths.delete(0, "end")
        for path in settings.get("monitor_paths") or []:
            self.monitor_paths.insert("end", path)
        for key, var in self.auto_vars.items():
            var.set(key in (settings.get("automatic_actions") or []))
        for key, widget in self.scope_texts.items():
            self._set_text(widget, "\n".join(settings.get(key) or []))

    def _render_events(self) -> None:
        selected = self.event_tree.selection()
        old = selected[0] if selected else None
        filtered = []
        choice = self.event_filter.get()
        for event in self._status.get("events") or []:
            kind = str(event.get("kind", "")).lower()
            if choice == "Alertes" and event.get("severity") not in {"warning", "critical"}:
                continue
            if choice == "Fichiers" and not any(word in kind for word in ("file", "scan", "antivirus", "quarantine")):
                continue
            if choice == "Réseau" and not any(word in kind for word in ("network", "connection", "ip", "cloud", "auth", "intrusion")):
                continue
            if choice == "Ressources" and not any(word in kind for word in ("cpu", "memory", "resource", "process")):
                continue
            filtered.append(event)
        self._event_rows = {str(event.get("id", i)): event for i, event in enumerate(filtered)}
        self._replace_tree(self.event_tree, [(key, (_clock(event.get("timestamp")), event.get("severity", "info"), event.get("kind", ""), event.get("summary", ""))) for key, event in self._event_rows.items()])
        if old in self._event_rows:
            self.event_tree.selection_set(old)

    @staticmethod
    def _replace_tree(tree: ttk.Treeview, rows: list[tuple[str, tuple]]) -> None:
        # Reconcile rows instead of deleting everything, retaining scroll position.
        existing = set(tree.get_children())
        wanted = {key for key, values in rows}
        for key in existing - wanted:
            tree.delete(key)
        for index, (key, values) in enumerate(rows):
            values = tuple(str(value if value is not None else "—")[:900] for value in values)
            if key in existing:
                if tuple(tree.item(key, "values")) != values:
                    tree.item(key, values=values)
                tree.move(key, "", index)
            else:
                tree.insert("", index, iid=key, values=values)

    def _render_system(self, snapshot: dict) -> None:
        rows = []
        for i, proc in enumerate(snapshot.get("processes") or []):
            rows.append((f"p{i}", (proc.get("pid"), proc.get("name"), proc.get("username"), proc.get("exe"))))
        self._replace_tree(self.process_tree, rows)
        rows = []
        for i, conn in enumerate(snapshot.get("connections") or []):
            rows.append((f"c{i}", (conn.get("pid"), conn.get("local"), conn.get("remote"), conn.get("status"))))
        self._replace_tree(self.connection_tree, rows)

    def _render_journal(self, status: dict) -> None:
        journal = status.get("journal") or {}
        valid = journal.get("valid", journal.get("ok"))
        self.journal_note.configure(text="Journal local · " + ("chaîne vérifiée" if valid is True else "anomalie d’intégrité à examiner" if valid is False else "vérification non disponible") + " · Un journal local ne protège pas à lui seul contre un administrateur hostile.")
        self._action_rows = {str(action.get("id", i)): action for i, action in enumerate(status.get("actions") or [])}
        self._replace_tree(self.action_tree, [(key, (_clock(action.get("timestamp")), action.get("action", action.get("type", "")), action.get("status", ""), action.get("reason", action.get("message", action.get("error", ""))))) for key, action in self._action_rows.items()])
        calls = status.get("calls") or []
        self._call_rows = {f"call{i}": call for i, call in enumerate(calls)}
        rows = []
        errors = 0
        for key, call in self._call_rows.items():
            callstatus = call.get("status", call.get("status_code", "n.d."))
            usage = call.get("usage") or {}
            tokens = call.get("tokens", usage.get("total_tokens", "n.d.") if isinstance(usage, dict) else "n.d.")
            if str(callstatus).lower() in {"error", "failed", "failure"} or (isinstance(callstatus, int) and callstatus >= 400):
                errors += 1
            rows.append((key, (_clock(call.get("timestamp")), call.get("operation", call.get("name", call.get("endpoint", "API"))), callstatus, _number(call.get("latency_ms", call.get("duration_ms"))), tokens, call.get("detail", call.get("error_code", call.get("error", ""))))))
        self._replace_tree(self.call_tree, rows)
        self.call_note.configure(text=f"{len(calls)} appel(s) affiché(s) · {errors} erreur(s) · « n.d. » : mesure non fournie par l’API")

    def _render_autonomy(self, status: dict) -> None:
        settings = status.get("settings") or {}
        running = bool(status.get("running") or status.get("external_monitor"))
        enabled = settings.get("autonomous_analysis_enabled", False)
        cloud = status.get("cloud") or {}
        analysis = "activée, selon budget" if enabled and cloud.get("enabled") and cloud.get("configured") else "en attente du Cloud" if enabled else "désactivée"
        self.autonomy_note.configure(text=f"Veille locale : {'active' if running else 'en pause'} · Analyse SAWM : {analysis} · Notifications système : {'autorisées' if settings.get('notifications_enabled', False) else 'désactivées'}")
        self._notification_rows = {str(row.get("id", i)): row for i, row in enumerate(status.get("notifications") or [])}
        unread = sum(not row.get("acknowledged") for row in self._notification_rows.values())
        self.notification_note.configure(text=f"Alertes · {unread} non lue(s)")
        deliveries = {"submitted": "Soumise à l’OS", "disabled": "Désactivée", "unavailable": "Indisponible", "error": "Échec", "suppressed": "Regroupée", "recorded": "Enregistrée"}
        self._replace_tree(self.notification_tree, [(key, (_clock(row.get("timestamp")), row.get("severity", "info"), "Lue" if row.get("acknowledged") else "Non lue", deliveries.get(row.get("delivery"), row.get("delivery", "n.d.")), row.get("summary", ""))) for key, row in self._notification_rows.items()])
        self._order_rows = {str(row.get("id", i)): row for i, row in enumerate(status.get("orders") or [])}
        labels = {"pending": "En attente", "running": "En cours", "completed": "Terminée", "failed": "Échec", "needs_review": "À examiner", "expired": "Expirée", "cancelled": "Annulée"}
        rows = []
        for key, row in self._order_rows.items():
            actor = row.get("actor") or {}
            actor_name = actor.get("username", "Session locale") if isinstance(actor, dict) else str(actor)
            payload = row.get("payload") or {}
            detail = row.get("error") or payload.get("path") or payload.get("event_id") or "Ouvrir pour les détails"
            rows.append((key, (_clock(row.get("created_at")), row.get("kind", ""), labels.get(row.get("status"), row.get("status", "n.d.")), actor_name, detail)))
        self._replace_tree(self.order_tree, rows)

    def _show_notification(self, _event=None) -> None:
        selected = self.notification_tree.selection()
        if selected and selected[0] in self._notification_rows:
            self._result_window("Notification et livraison au système", self._notification_rows[selected[0]])

    def _acknowledge_notification(self) -> None:
        selected = self.notification_tree.selection()
        if self.service is not None and selected:
            notification_id = selected[0]
            self._submit("notification_ack", "Accusé de lecture", lambda: self.service.acknowledge_notification(notification_id))

    def _show_order(self, _event=None) -> None:
        selected = self.order_tree.selection()
        if selected and selected[0] in self._order_rows:
            self._result_window("Mission et résultat vérifié", self._order_rows[selected[0]])

    def _submit_mission(self) -> None:
        if self.service is None:
            return
        choice = self.mission_kind.get()
        kind, payload = "inventory", {}
        if choice == "Analyser un fichier":
            path = filedialog.askopenfilename(title="Choisir un fichier du périmètre surveillé", parent=self.root)
            if not path:
                return
            kind, payload = "scan", {"path": path}
        elif choice == "Analyser une observation":
            event = self._selected_event()
            if not event:
                messagebox.showinfo("Mission", "Sélectionnez une observation dans l’onglet Observations, puis revenez confier la mission.", parent=self.root)
                return
            kind, payload = "analyze", {"event_id": event["id"]}
        elif choice == "Produire un rapport":
            path = filedialog.asksaveasfilename(title="Destination du rapport de mission", parent=self.root, initialfile=f"SAWM-Defense-{datetime.now().strftime('%Y-%m-%d')}.html", defaultextension=".html", filetypes=[("Rapport HTML", "*.html"), ("Données JSON", "*.json")])
            if not path:
                return
            kind, payload = "report", {"path": path}
        def submitted(result):
            state = result.get("status", "enregistrée") if isinstance(result, dict) else "enregistrée"
            self.status_text.configure(text=f"Mission : {state}. Son résultat apparaîtra dans cette liste.")
        self._submit("mission", "Enregistrement de la mission", lambda: self.service.submit_order(kind, payload, approved=False), submitted)

    def _draw_chart(self) -> None:
        if not hasattr(self, "chart"):
            return
        chart = self.chart
        chart.delete("all")
        w, h = max(200, chart.winfo_width()), max(120, chart.winfo_height())
        left, right, top, bottom = 35, w - 12, 28, h - 28
        for percent in (0, 50, 100):
            y = bottom - (bottom - top) * percent / 100
            chart.create_line(left, y, right, y, fill=EDGE, dash=(2, 5))
            chart.create_text(left - 8, y, text=str(percent), fill=SOFT, anchor="e", font=(self.font, 9))
        if not self._history:
            chart.create_text((left + right) / 2, (top + bottom) / 2, text="En attente d’échantillons réels", fill=MUTED, font=(self.font, 11))
            return
        values = list(self._history)
        for series, color, dash in [(0, TEXT, ()), (1, SOFT, (4, 3))]:
            points = []
            for i, pair in enumerate(values):
                value = pair[series]
                if not isinstance(value, (int, float)):
                    continue
                x = left + (right - left) * i / max(1, len(values) - 1)
                y = bottom - (bottom - top) * max(0, min(100, value)) / 100
                points.extend((x, y))
            if len(points) >= 4:
                chart.create_line(*points, fill=color, width=2, dash=dash)
            elif len(points) == 2:
                x, y = points
                chart.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline=color)
        latest = values[-1]
        chart.create_text(left, 9, text=f"CPU  {_number(latest[0], ' %')}", fill=TEXT, anchor="w", font=(self.font, 10, "bold"))
        chart.create_text(right, 9, text=f"RAM  {_number(latest[1], ' %')}", fill=MUTED, anchor="e", font=(self.font, 10))
        chart.create_text(left, h - 7, text=f"{len(values)} échantillons de cette session", fill=SOFT, anchor="w", font=(self.font, 9))

    def _toggle_monitor(self) -> None:
        if self.service is None:
            return
        def result(value):
            if isinstance(value, dict) and value.get("status") in {"denied", "error", "busy"}:
                self._result_window("Surveillance", value)
        if self._status.get("running"):
            self._submit("monitor", "Mise en pause", self.service.stop, result)
        else:
            self._submit("monitor", "Démarrage de la surveillance", self.service.start, result)

    def _add_folder(self) -> None:
        path = filedialog.askdirectory(title="Choisir un dossier à surveiller", parent=self.root)
        if path and path not in self.monitor_paths.get(0, "end"):
            self.monitor_paths.insert("end", path)

    def _remove_folder(self) -> None:
        for index in reversed(self.monitor_paths.curselection()):
            self.monitor_paths.delete(index)

    def _save_settings(self, check: bool = False) -> None:
        if self.service is None:
            return
        try:
            patch = {key: var.get() for key, var in self._vars.items() if key not in {"api_key", "persist_key"}}
            for key in ("poll_seconds", "cloud_per_hour", "max_file_mb", "retention_days", "auth_failure_threshold", "auth_window_seconds", "auto_block_seconds", "download_scan_settle_seconds"):
                patch[key] = int(patch[key])
            patch["monitor_paths"] = list(self.monitor_paths.get(0, "end"))
            patch["automatic_actions"] = [key for key, var in self.auto_vars.items() if var.get()]
            patch.update({key: _lines(widget.get("1.0", "end")) for key, widget in self.scope_texts.items()})
        except (ValueError, tk.TclError):
            messagebox.showerror("Réglages", "Les intervalles, limites et durées doivent être des nombres entiers.", parent=self.root)
            return
        original = set((self._status.get("settings") or {}).get("automatic_actions") or [])
        expanded = set(patch["automatic_actions"]) - original
        old_settings = self._status.get("settings") or {}
        if patch.get("autoblock_auth_ips") and not old_settings.get("autoblock_auth_ips"):
            expanded.add("blocage temporaire des sources SSH attribuées")
        if expanded and not messagebox.askokcancel("Autoriser des interventions automatiques", "Vous autorisez : " + ", ".join(sorted(expanded)) + ".\n\nCes interventions restent soumises aux preuves locales et aux périmètres. Un arrêt de processus peut perdre son travail ; un blocage IP peut couper un accès. Le blocage des sources SSH utilise un journal système fiable et les IP protégées sont exclues. Vérifiez ces réglages avant de confirmer.", parent=self.root):
            return
        key = self._vars["api_key"].get().strip() or None
        persist = bool(self._vars["persist_key"].get())

        def saved(result):
            self._vars["api_key"].set("")
            self.status_text.configure(text="Réglages enregistrés.")
            if check:
                self._submit("cloud_check", "Vérification des accès Cloud", self.service.check_connection, lambda value: self._result_window("Accès Cloud", value))

        self._submit("settings", "Enregistrement des réglages", lambda: self.service.save_settings(patch, api_key=key, persist_key=persist), saved)

    def _startup(self, enable: bool) -> None:
        if self.service is None:
            return
        verb = "activer" if enable else "désactiver"
        detail = "Le service utilisateur surveillera les périmètres enregistrés après ouverture de session. Les accès Cloud et permissions restent ceux des réglages sauvegardés." if enable else "Le démarrage automatique de SAWM Defense sera retiré pour cet utilisateur."
        if messagebox.askokcancel("Démarrage automatique", f"Voulez-vous {verb} le démarrage automatique ?\n\n{detail}", parent=self.root):
            operation = self.service.install_startup if enable else self.service.remove_startup
            self._submit("startup", "Configuration du démarrage", operation, lambda result: self._result_window("Démarrage automatique", result))

    def _scan(self) -> None:
        if self.service is None:
            return
        path = filedialog.askopenfilename(title="Analyser un fichier d’un dossier surveillé", parent=self.root)
        if path:
            self._submit("scan", "Inspection locale du fichier", lambda: self.service.scan(path), lambda result: self._result_window("Résultat de l’analyse locale", result))

    def _inventory(self) -> None:
        if self.service is not None:
            self._submit("inventory", "Inventaire des logiciels", self.service.inventory, lambda result: self._result_window("Logiciels installés — inventaire observé", result))

    def _selected_event(self) -> dict | None:
        selected = self.event_tree.selection()
        return self._event_rows.get(selected[0]) if selected else None

    def _show_event(self, _event=None) -> None:
        event = self._selected_event()
        if event:
            self._set_text(self.event_detail, _display(event))

    def _analyze_event(self) -> None:
        event = self._selected_event()
        if not event or self.service is None:
            messagebox.showinfo("Observation", "Sélectionnez d’abord une observation.", parent=self.root)
            return

        def analyzed(result):
            self._append_chat("SAWM / ANALYSE D’OBSERVATION", _display(result))
            self.tabs.select(self.pages["chat"])

        self._submit("analysis", "Analyse de l’observation par SAWM", lambda: self.service.analyze(event.get("id")), analyzed)

    def _act(self) -> None:
        event = self._selected_event()
        if not event or self.service is None:
            messagebox.showinfo("Action", "Sélectionnez d’abord une observation attribuée à la cible.", parent=self.root)
            return
        action = {"Mettre en quarantaine": "quarantine", "Arrêter le processus": "terminate", "Bloquer l’IP autorisée": "block_ip"}[self.manual_action.get()]
        details = event.get("details") or {}
        target = details.get("path", details.get("pid", details.get("remote_ip", details.get("remote", "Voir les preuves de l’événement"))))
        if not messagebox.askokcancel("Autoriser une action sur cette cible", f"Action : {self.manual_action.get()}\nCible : {target}\nÉvénement : {event.get('id')}\n\nL’exécuteur vérifiera à nouveau le périmètre, les permissions et l’identité de la cible. Cette action sera journalisée.", parent=self.root):
            return
        self._submit("action", "Vérification et exécution de l’action", lambda: self.service.act(action, event.get("id"), approved=True), lambda result: self._result_window("Reçu d’action", result))

    def _show_action(self) -> None:
        selected = self.action_tree.selection()
        if selected and selected[0] in self._action_rows:
            self._result_window("Reçu d’action", self._action_rows[selected[0]])

    def _restore(self) -> None:
        selected = self.action_tree.selection()
        if not selected or self.service is None:
            messagebox.showinfo("Retour arrière", "Sélectionnez d’abord une action dans le journal.", parent=self.root)
            return
        action = self._action_rows[selected[0]]
        if not messagebox.askokcancel("Autoriser le retour arrière", "Demander l’annulation de cette action ?\n\n" + _display(action, 1400) + "\n\nUne restauration refuse d’écraser un fichier existant. Un processus arrêté ne peut pas être recréé automatiquement.", parent=self.root):
            return
        self._submit("restore", "Retour arrière contrôlé", lambda: self.service.restore(action.get("id"), approved=True), lambda result: self._result_window("Résultat du retour arrière", result))

    def _show_call(self, _event=None) -> None:
        selected = self.call_tree.selection()
        if selected:
            self._result_window("Reçu d’appel Cloud", self._call_rows.get(selected[0], {}))

    def _send_chat(self, _event=None):
        if self.service is None or self._chat_pending:
            return "break"
        message = self.chat_input.get("1.0", "end").strip()
        if not message:
            return "break"
        self._chat_pending = True
        self.chat_send.configure(state="disabled")
        self._append_chat("VOUS", message)
        self.chat_input.delete("1.0", "end")

        def received(result):
            self._chat_finished()
            self._append_chat("SAWM", str(result.get("text") or result.get("message") or _display(result)))
            usage = result.get("usage")
            if usage:
                self._append_chat("CONSOMMATION FOURNIE PAR L’API", _display(usage))

        if not self._submit("chat", "Dialogue avec SAWM", lambda: self.service.chat(message), received):
            self._chat_finished()
        return "break"

    def _chat_finished(self) -> None:
        self._chat_pending = False
        self.chat_send.configure(state="normal")

    def _append_chat(self, role: str, text: str) -> None:
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", f"\n\n{role}  ·  {datetime.now().strftime('%H:%M')}\n\n{text}\n")
        self.chat_history.configure(state="disabled")
        self.chat_history.see("end")

    def _export(self) -> None:
        if self.service is None:
            return
        path = filedialog.asksaveasfilename(title="Exporter le rapport d’activité", parent=self.root,
                                          initialfile=f"SAWM-Defense-{datetime.now().strftime('%Y-%m-%d')}.html",
                                          defaultextension=".html", filetypes=[("Rapport HTML", "*.html"), ("Données JSON", "*.json")])
        if path:
            self._submit("export", "Export du rapport local", lambda: self.service.export_report(path), lambda result: messagebox.showinfo("Rapport exporté", f"Rapport enregistré :\n{result}\n\nLe rapport peut contenir des chemins, adresses et noms d’utilisateur. Partagez-le avec les personnes autorisées.", parent=self.root))

    def _result_window(self, title: str, result: Any) -> None:
        window = tk.Toplevel(self.root)
        window.title("SAWM Defense · " + title)
        window.geometry("830x570")
        window.minsize(600, 350)
        window.configure(background=BG)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)
        ttk.Label(window, text=title, style="Section.TLabel", wraplength=780).grid(row=0, column=0, sticky="w", padx=20, pady=20)
        text = self._text(window, height=18)
        text.grid(row=1, column=0, sticky="nsew", padx=20)
        self._set_text(text, _display(result, 60000))
        ttk.Button(window, text="Fermer", command=window.destroy).grid(row=2, column=0, sticky="e", padx=20, pady=15)

    def _close(self) -> None:
        if self._closing:
            return
        if self._status.get("running") and not self._status.get("external_monitor"):
            if not messagebox.askokcancel("Quitter SAWM Defense", "Quitter la console arrête la surveillance de cette session. Un service de démarrage installé séparément conserve sa propre surveillance.\n\nVoulez-vous quitter ?", parent=self.root):
                return
        self._closing = True
        if self._poll_timer:
            self.root.after_cancel(self._poll_timer)
        self.status_text.configure(text="Fermeture de la console…")
        done = threading.Event()

        def finish():
            try:
                # No new UI job can start after _closing. Manual scan/chat work
                # must finish before AgentService closes its stores. Waiting is
                # done here, never on Tk's thread and never with a forced timer.
                while True:
                    with self._workers_lock:
                        workers = tuple(self._workers)
                    if not workers:
                        break
                    for worker in workers:
                        worker.join()
                with self._workers_lock:
                    service = self.service or self._created_service
                if service is not None:
                    service.close()
            finally:
                done.set()

        threading.Thread(target=finish, name="sawm-ui-close", daemon=True).start()
        checks = 0

        def destroy_when_closed():
            nonlocal checks
            checks += 1
            if done.is_set():
                self.root.destroy()
            else:
                if checks == 30:
                    self.status_text.configure(text="Finalisation des opérations en cours et du journal local…")
                self.root.after(100, destroy_when_closed)

        self.root.after(100, destroy_when_closed)


def main(state_dir: str | Path | None = None) -> None:
    root = tk.Tk()
    DefenseApp(root, state_dir=state_dir)
    root.mainloop()


if __name__ == "__main__":
    main()
