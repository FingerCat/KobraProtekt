"""Kobra Protekt — application Windows (interface HUD de visée).

Menu : Analyser · Mettre à jour · Sources · Bilan · Historique.
Dès qu'une menace est détectée, elle « passe dans la cible » (verrouillage)
avant d'être mise en quarantaine ou supprimée (avec confirmation).
Enquête = infrastructure uniquement. Signalement = dossier auto + envoi validé.
"""
from __future__ import annotations
import os
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, scrolledtext

from . import theme as T
from . import report as rpt
from . import scanner
from .hud import HudCanvas
from .investigate import investigate
from .report_policy import Decision, HUMAN, evaluate
from .signatures import SignatureDB, update as update_feeds
from .store import History, Prefs

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")


def asset(name):  # gère aussi le mode PyInstaller (_MEIPASS)
    base = getattr(sys, "_MEIPASS", None)
    if base:
        p = os.path.join(base, "assets", name)
        if os.path.exists(p):
            return p
    return os.path.join(ASSETS, name)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kobra Protekt")
        self.configure(bg=T.BG)
        self.geometry("1040x720")
        self.minsize(900, 640)
        try:
            self.iconbitmap(asset("kobra.ico"))
        except Exception:  # noqa: BLE001 (pas d'icône sous Linux)
            pass

        self.db = SignatureDB.load()
        self.prefs = Prefs()
        self.history = History()
        self.findings: list[scanner.Finding] = []
        self._logo_img = None

        self._build_header()
        self._build_hud()
        self._build_menu()
        self._build_results()
        self._build_statusline()
        self._refresh_db_status()

    # ---------------- construction UI ----------------
    def _build_header(self):
        bar = tk.Frame(self, bg=T.BG)
        bar.pack(fill="x", pady=(10, 0))
        try:
            self._logo_img = tk.PhotoImage(file=asset("wordmark.png"))
            tk.Label(bar, image=self._logo_img, bg=T.BG).pack()
        except Exception:  # noqa: BLE001
            tk.Label(bar, text="K O B R A   P R O T E K T", font=T.TITLE,
                     fg=T.GOLD, bg=T.BG).pack()
        tk.Label(bar, text="Détection de logiciels espions et d'applications malveillantes",
                 font=T.MONO_S, fg=T.TEXT_DIM, bg=T.BG).pack()

    def _build_hud(self):
        wrap = tk.Frame(self, bg=T.BG)
        wrap.pack(fill="x", padx=16, pady=8)
        self.hud = HudCanvas(wrap, width=1000, height=300)
        self.hud.pack(fill="x")

    def _hud_button(self, parent, text, cmd):
        b = tk.Button(parent, text=text, command=cmd, font=T.MONO,
                      fg=T.GOLD, bg=T.SURFACE, activebackground=T.GOLD_DIM,
                      activeforeground=T.BG, relief="flat", bd=0,
                      highlightbackground=T.GOLD, highlightthickness=1,
                      padx=14, pady=8, cursor="hand2")
        b.pack(side="left", padx=5)
        return b

    def _build_menu(self):
        m = tk.Frame(self, bg=T.BG)
        m.pack(fill="x", padx=16)
        self.btn_scan = self._hud_button(m, "▶ ANALYSER", self.on_scan)
        self._hud_button(m, "⟳ METTRE À JOUR", self.on_update)
        self._hud_button(m, "⌖ BILAN APPAREIL", self.on_scan)
        self._hud_button(m, "⚙ SOURCES", self.on_sources)
        self._hud_button(m, "▣ HISTORIQUE", self.on_history)

    def _build_results(self):
        frame = tk.Frame(self, bg=T.BG)
        frame.pack(fill="both", expand=True, padx=16, pady=8)
        tk.Label(frame, text="RÉSULTATS", font=T.MONO, fg=T.HUD_CYAN,
                 bg=T.BG, anchor="w").pack(fill="x")
        cont = tk.Frame(frame, bg=T.BG)
        cont.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(cont, bg=T.BG, highlightthickness=0)
        sb = tk.Scrollbar(cont, orient="vertical", command=self.canvas.yview)
        self.results = tk.Frame(self.canvas, bg=T.BG)
        self.results.bind("<Configure>",
                          lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.results, anchor="nw", width=980)
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def _build_statusline(self):
        self.status = tk.Label(self, text="", font=T.MONO_S, fg=T.TEXT_DIM,
                               bg=T.BG, anchor="w")
        self.status.pack(fill="x", padx=16, pady=(0, 8))

    # ---------------- helpers ----------------
    def log(self, text: str):
        self.status.config(text=text)

    def _refresh_db_status(self):
        if self.db.total == 0:
            self.log("Base de signatures vide : lancez « Mettre à jour ».")
        else:
            import datetime
            when = datetime.datetime.fromtimestamp(self.db.updated).strftime("%Y-%m-%d %H:%M")
            self.log(f"Base : {self.db.total} indicateurs · mise à jour {when}")

    def _clear_results(self):
        for w in self.results.winfo_children():
            w.destroy()

    # ---------------- mise à jour des listes ----------------
    def on_update(self):
        self.log("Mise à jour des listes…")

        def work():
            mb = self.prefs.get("mb_key")
            extra = [u for u in self.prefs.get("extra_urls", "").splitlines() if u.strip()]
            loglines = update_feeds(self.db, mb_key=mb, extra_urls=extra,
                                    progress=lambda s: self.after(0, self.log, s))
            self.after(0, lambda: (self._refresh_db_status(),
                                   messagebox.showinfo("Mise à jour", "\n".join(loglines))))
        threading.Thread(target=work, daemon=True).start()

    # ---------------- analyse ----------------
    def on_scan(self):
        if self.db.total == 0:
            if not messagebox.askyesno("Analyse",
                    "La base de signatures est vide. Analyser quand même "
                    "(comportement seulement) ?"):
                return
        self.btn_scan.config(state="disabled")
        self._clear_results()
        self.findings = []
        self.hud.set_status("ANALYSE EN COURS…")
        self.log("Analyse en cours…")

        def prog(phase, a, b):
            self.after(0, self.log, f"Analyse ({phase}) : {a}/{b}")

        def work():
            results = scanner.full_scan(self.db, progress=prog)
            self.after(0, self._present_results, results)

        threading.Thread(target=work, daemon=True).start()

    def _present_results(self, results: list[scanner.Finding]):
        self.findings = results
        if not results:
            self.hud.set_status("AUCUNE MENACE")
            self.log("Analyse terminée : aucune menace connue détectée.")
            tk.Label(self.results, text="Aucune menace détectée.", font=T.MONO,
                     fg=T.RESOLVED, bg=T.BG, anchor="w").pack(fill="x", pady=6)
            self.btn_scan.config(state="normal")
            return
        n_threat = sum(1 for f in results if f.verdict == scanner.THREAT)
        self.log(f"Analyse terminée : {n_threat} menace(s), "
                 f"{len(results) - n_threat} à vérifier.")
        # chaque menace « passe dans la cible » puis s'affiche
        self._acquire_queue = list(results)
        self._acquire_next()

    def _acquire_next(self):
        if not self._acquire_queue:
            self.hud.set_status("SYSTÈME PRÊT")
            self.btn_scan.config(state="normal")
            self.history.add("scan", f"{len(self.findings)} élément(s) signalé(s)")
            return
        f = self._acquire_queue.pop(0)
        self.hud.acquire(f.title, f.verdict, on_done=lambda: (self._add_finding_row(f),
                                                              self._acquire_next()))

    def _add_finding_row(self, f: scanner.Finding):
        col = T.THREAT if f.verdict == scanner.THREAT else T.WARNING
        tag = "MENACE" if f.verdict == scanner.THREAT else "À VÉRIFIER"
        row = tk.Frame(self.results, bg=T.SURFACE, highlightbackground=col,
                       highlightthickness=1)
        row.pack(fill="x", pady=4, padx=2)
        head = tk.Frame(row, bg=T.SURFACE)
        head.pack(fill="x", padx=10, pady=(8, 2))
        tk.Label(head, text=f"[{tag}] {f.title}", font=T.MONO, fg=col,
                 bg=T.SURFACE, anchor="w").pack(side="left")
        if f.path:
            tk.Label(row, text=f.path, font=T.MONO_S, fg=T.TEXT_DIM, bg=T.SURFACE,
                     anchor="w", wraplength=900, justify="left").pack(fill="x", padx=10)
        for r in f.reasons:
            tk.Label(row, text="• " + r, font=T.MONO_S, fg=T.TEXT, bg=T.SURFACE,
                     anchor="w", wraplength=900, justify="left").pack(fill="x", padx=16)
        actions = tk.Frame(row, bg=T.SURFACE)
        actions.pack(fill="x", padx=10, pady=8)
        if f.path and os.path.isfile(f.path):
            self._mini(actions, "Mettre en quarantaine", lambda: self.on_quarantine(f, row))
            self._mini(actions, "Supprimer", lambda: self.on_delete(f, row), danger=True)
        if f.pid:
            self._mini(actions, "Arrêter le processus", lambda: self.on_kill(f))
        self._mini(actions, "Enquêter (infrastructure)", lambda: self.on_investigate(f))

    def _mini(self, parent, text, cmd, danger=False):
        tk.Button(parent, text=text, command=cmd, font=T.MONO_S,
                  fg=(T.THREAT if danger else T.GOLD), bg=T.BG,
                  activebackground=T.GOLD_DIM, relief="flat",
                  highlightbackground=(T.THREAT if danger else T.GOLD),
                  highlightthickness=1, padx=8, pady=3, cursor="hand2").pack(side="left", padx=4)

    # ---------------- actions sur une menace ----------------
    def on_quarantine(self, f, row):
        if not messagebox.askyesno("Quarantaine",
                f"Déplacer vers la quarantaine ?\n\n{f.path}"):
            return
        try:
            from .signatures import APP_DIR
            qdir = os.path.join(APP_DIR, "quarantaine")
            os.makedirs(qdir, exist_ok=True)
            dest = os.path.join(qdir, os.path.basename(f.path) + ".quarantine")
            os.replace(f.path, dest)
            self.history.add("quarantaine", f.title, dest)
            messagebox.showinfo("Quarantaine", "Déplacé en quarantaine.")
            row.destroy()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Quarantaine", f"Échec : {e}")

    def on_delete(self, f, row):
        if not messagebox.askyesno("Suppression",
                f"Supprimer définitivement ce fichier ?\n\n{f.path}\n\n"
                "Cette action est irréversible."):
            return
        try:
            os.remove(f.path)
            self.history.add("suppression", f.title, f.path)
            messagebox.showinfo("Suppression", "Fichier supprimé.")
            row.destroy()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Suppression", f"Échec : {e}")

    def on_kill(self, f):
        if not messagebox.askyesno("Processus", f"Arrêter le processus PID {f.pid} ?"):
            return
        try:
            if scanner.IS_WIN:
                import subprocess
                subprocess.run(["taskkill", "/PID", str(f.pid), "/F"], timeout=10)
            else:
                os.kill(f.pid, 9)
            self.history.add("arrêt processus", f.title, f"PID {f.pid}")
            messagebox.showinfo("Processus", "Processus arrêté.")
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Processus", f"Échec : {e}")

    # ---------------- enquête + signalement ----------------
    def on_investigate(self, f: scanner.Finding):
        indicator = f.remote_ip or f.remote_host
        if not indicator:
            # fichier/processus : pas d'indicateur réseau exploitable ici
            messagebox.showinfo("Enquête",
                "Aucune adresse de serveur relevée pour cet élément. "
                "L'enquête réseau vise les connexions vers un serveur de commande (C2).")
            return
        win = tk.Toplevel(self, bg=T.BG)
        win.title(f"Enquête — {indicator}")
        win.geometry("680x560")
        box = scrolledtext.ScrolledText(win, bg=T.SURFACE, fg=T.TEXT,
                                        insertbackground=T.GOLD, font=T.MONO_S, wrap="word")
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("end", "Identification de l'infrastructure (registres publics)…\n"
                          "Le serveur suspect n'est jamais contacté.\n\n")
        bar = tk.Frame(win, bg=T.BG)
        bar.pack(fill="x", padx=10, pady=(0, 10))

        def work():
            inv = investigate(indicator, abuse_key=self.prefs.get("abuse_key"))
            dossier = rpt.build_dossier(f, inv)
            decision = evaluate(f.confirmed, inv.net_info.ip or (inv.ips[0] if inv.ips else ""),
                                inv.net_info)

            def show():
                box.insert("end", dossier + "\n\n")
                box.insert("end", "GARDE-FOU DE SIGNALEMENT\n  " + HUMAN[decision] + "\n")
                box.see("1.0")
                self._mini(bar, "Enregistrer le dossier",
                           lambda: self._save_dossier(dossier, indicator))
                if decision == Decision.ALLOWED:
                    self._mini(bar, "► Signaler (avec validation)",
                               lambda: self._report_flow(f, inv, dossier), danger=True)
                else:
                    tk.Label(bar, text="Signalement bloqué par les garde-fous.",
                             font=T.MONO_S, fg=T.TEXT_DIM, bg=T.BG).pack(side="left", padx=6)
            self.after(0, show)

        threading.Thread(target=work, daemon=True).start()

    def _save_dossier(self, dossier: str, indicator: str):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"dossier_{indicator.replace('.', '-')}.txt",
            filetypes=[("Texte", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(dossier)
        self.history.add("dossier", indicator, path)
        messagebox.showinfo("Dossier", f"Enregistré :\n{path}")

    def _report_flow(self, f, inv, dossier):
        """Dossier auto déjà compilé ; envoi uniquement après validation explicite."""
        ip = inv.net_info.ip or (inv.ips[0] if inv.ips else "")
        channels = []
        if inv.net_info.abuse_email:
            channels.append(f"• Courriel à l'hébergeur ({inv.net_info.abuse_email}) — "
                            "s'ouvre dans votre messagerie, à relire avant envoi")
        if self.prefs.get("abuse_key"):
            channels.append(f"• AbuseIPDB — publication du signalement de {ip}")
        channels.append("• cybermalveillance.gouv.fr — ouverture du portail officiel (France)")
        msg = ("Le dossier de preuves est prêt. Les envois suivants seront effectués "
               "APRÈS votre validation :\n\n" + "\n".join(channels) +
               "\n\nRappel : une IP ne prouve pas l'identité d'une personne. "
               "Confirmez-vous l'envoi ?")
        if not messagebox.askyesno("Signalement — validation", msg):
            return
        # 1) courriel hébergeur
        if inv.net_info.abuse_email:
            try:
                webbrowser.open(rpt.abuse_email_mailto(inv, dossier))
            except Exception:  # noqa: BLE001
                pass
        # 2) AbuseIPDB (action réelle, seulement si clé + validé)
        if self.prefs.get("abuse_key") and ip:
            try:
                rpt.submit_abuseipdb(ip, dossier, self.prefs.get("abuse_key"))
                self.history.add("signalement AbuseIPDB", ip)
            except Exception as e:  # noqa: BLE001
                messagebox.showwarning("AbuseIPDB", f"Non publié : {e}")
        # 3) portail officiel
        webbrowser.open(rpt.CYBERMALVEILLANCE)
        self.history.add("signalement", f.title, ip)
        messagebox.showinfo("Signalement",
            "Courriel ouvert (à relire et envoyer), portail officiel ouvert. "
            "Conservez le dossier comme preuve.")

    # ---------------- sources ----------------
    def on_sources(self):
        win = tk.Toplevel(self, bg=T.BG)
        win.title("Sources & clés")
        win.geometry("620x520")
        tk.Label(win, text="Clés de services (gratuites, facultatives)", font=T.MONO,
                 fg=T.GOLD, bg=T.BG).pack(anchor="w", padx=12, pady=(12, 4))
        fields = {}
        for key, label in [("mb_key", "Clé MalwareBazaar (abuse.ch)"),
                           ("abuse_key", "Clé AbuseIPDB (enquête & signalement)")]:
            tk.Label(win, text=label, font=T.MONO_S, fg=T.TEXT, bg=T.BG).pack(anchor="w", padx=12)
            e = tk.Entry(win, bg=T.SURFACE, fg=T.TEXT, insertbackground=T.GOLD,
                         font=T.MONO_S, width=60)
            e.insert(0, self.prefs.get(key))
            e.pack(anchor="w", padx=12, pady=(0, 8))
            fields[key] = e
        tk.Label(win, text="Listes supplémentaires (1 URL https par ligne, max 10)",
                 font=T.MONO_S, fg=T.TEXT, bg=T.BG).pack(anchor="w", padx=12)
        txt = tk.Text(win, bg=T.SURFACE, fg=T.TEXT, insertbackground=T.GOLD,
                      font=T.MONO_S, height=8, width=60)
        txt.insert("1.0", self.prefs.get("extra_urls", ""))
        txt.pack(anchor="w", padx=12, pady=(0, 8))
        tk.Label(win, text="Confidentialité : sans clé, rien n'est envoyé à ces services ;\n"
                           "les listes sont téléchargées puis comparées sur la machine.",
                 font=T.MONO_S, fg=T.TEXT_DIM, bg=T.BG, justify="left").pack(anchor="w", padx=12)

        def save():
            for k, e in fields.items():
                self.prefs.set(k, e.get().strip())
            self.prefs.set("extra_urls", txt.get("1.0", "end").strip())
            win.destroy()
            messagebox.showinfo("Sources", "Enregistré.")
        tk.Button(win, text="Enregistrer", command=save, font=T.MONO, fg=T.BG,
                  bg=T.GOLD, relief="flat", padx=14, pady=6, cursor="hand2").pack(pady=10)

    # ---------------- historique ----------------
    def on_history(self):
        win = tk.Toplevel(self, bg=T.BG)
        win.title("Historique")
        win.geometry("640x520")
        box = scrolledtext.ScrolledText(win, bg=T.SURFACE, fg=T.TEXT, font=T.MONO_S, wrap="word")
        box.pack(fill="both", expand=True, padx=10, pady=10)
        if not self.history.events:
            box.insert("end", "Aucun événement.")
        for ev in self.history.events:
            box.insert("end", f"{ev['t']}  [{ev['action']}]  {ev['title']}\n")
            if ev.get("detail"):
                box.insert("end", f"            {ev['detail']}\n")
        box.config(state="disabled")

        def clear():
            if messagebox.askyesno("Historique", "Effacer tout l'historique ?"):
                self.history.clear(); win.destroy()
        tk.Button(win, text="Effacer", command=clear, font=T.MONO_S, fg=T.THREAT,
                  bg=T.BG, relief="flat", highlightbackground=T.THREAT,
                  highlightthickness=1, padx=10, pady=4).pack(pady=(0, 10))


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
