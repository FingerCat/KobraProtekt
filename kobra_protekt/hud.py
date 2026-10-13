"""Interface HUD de visée — grille, réticule central, télémétrie, balayage.

Reprend l'esthétique de l'écran de ciblage fourni : fond sombre, grille en
perspective, cercle de visée central avec croix et équerres, coins avec
télémétrie, ligne de balayage animée. La séquence `acquire()` fait passer une
menace détectée « dans la cible » (verrouillage) avant sa suppression.
"""
from __future__ import annotations
import math
import tkinter as tk

from . import theme as T


class HudCanvas(tk.Canvas):
    def __init__(self, master, width=760, height=460, **kw):
        super().__init__(master, width=width, height=height, bg=T.BG,
                         highlightthickness=0, **kw)
        self.W, self.H = width, height
        self._tick = 0
        self._sweep_y = 0
        self._status = "SYSTÈME PRÊT"
        self._locked = False
        self._anim_items = []
        self.bind("<Configure>", self._on_resize)
        self._draw_all()
        self.after(60, self._animate)

    # ---------- dessin ----------
    def _on_resize(self, e):
        self.W, self.H = e.width, e.height
        self._draw_all()

    def _grid(self):
        cx, cy = self.W / 2, self.H / 2
        # grille en perspective haut et bas (lignes vers un horizon central)
        for frac in [i / 12 for i in range(-6, 7)]:
            x = cx + frac * self.W * 0.9
            self.create_line(x, 0, cx, cy, fill=T.GRID_SOFT, width=1)
            self.create_line(x, self.H, cx, cy, fill=T.GRID_SOFT, width=1)
        for i in range(1, 7):
            k = (i / 6) ** 2
            y1 = cy - k * cy
            y2 = cy + k * cy
            self.create_line(0, y1, self.W, y1, fill=T.GRID_SOFT, width=1)
            self.create_line(0, y2, self.W, y2, fill=T.GRID_SOFT, width=1)

    def _corner_brackets(self):
        m, L = 16, 46
        pts = [(m, m, 1, 1), (self.W - m, m, -1, 1),
               (m, self.H - m, 1, -1), (self.W - m, self.H - m, -1, -1)]
        for x, y, sx, sy in pts:
            self.create_line(x, y, x + sx * L, y, fill=T.GOLD, width=2)
            self.create_line(x, y, x, y + sy * L, fill=T.GOLD, width=2)

    def _telemetry(self):
        self.create_text(22, 70, anchor="nw", font=T.MONO_S, fill=T.HUD_CYAN,
                         text="SECTEUR 25  |49|\nSECTEUR 32  |33|")
        self.create_text(self.W - 22, 70, anchor="ne", font=T.MONO_S, fill=T.HUD_CYAN,
                         text="BLOC 3  ▓▓▓░\nBLOC 4  ▓▓░░")
        self.create_text(22, self.H - 40, anchor="sw", font=T.MONO_S, fill=T.TEXT_DIM,
                         text="Cible  57.15.22")
        self.create_text(self.W - 22, self.H - 40, anchor="se", font=T.MONO_S, fill=T.TEXT_DIM,
                         text="Position 65.48.42")

    def _reticle(self, flash=False):
        cx, cy = self.W / 2, self.H / 2
        r = min(self.W, self.H) * 0.20
        col = T.THREAT if (flash or self._locked) else T.GOLD
        # anneau brisé
        for a0 in range(0, 360, 90):
            self.create_arc(cx - r, cy - r, cx + r, cy + r, start=a0 + 12,
                            extent=66, style="arc", outline=col, width=2)
        # ticks rotatifs
        for i in range(0, 360, 30):
            ang = math.radians(i + self._tick * 2)
            r1, r2 = r + 6, r + 14
            self.create_line(cx + r1 * math.cos(ang), cy + r1 * math.sin(ang),
                             cx + r2 * math.cos(ang), cy + r2 * math.sin(ang),
                             fill=T.GOLD_DIM, width=1)
        # croix centrale
        g = r * 0.5
        for dx, dy in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
            self.create_line(cx + dx * 8, cy + dy * 8,
                             cx + dx * g, cy + dy * g, fill=col, width=2)
        self.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, outline=col, width=1)
        # petites équerres internes
        q = r * 0.62
        for sx, sy in [(-1, -1), (1, -1), (-1, 1), (1, 1)]:
            self.create_line(cx + sx * q, cy + sy * q, cx + sx * (q - 12), cy + sy * q, fill=col)
            self.create_line(cx + sx * q, cy + sy * q, cx + sx * q, cy + sy * (q - 12), fill=col)

    def _status_bar(self):
        cx = self.W / 2
        col = T.THREAT if self._locked else T.HUD_CYAN
        self.create_text(cx, 24, font=T.MONO, fill=col, text=self._status)

    def _draw_all(self, flash=False):
        self.delete("all")
        self._grid()
        self._corner_brackets()
        self._telemetry()
        self._reticle(flash=flash)
        self._status_bar()
        # ligne de balayage
        self.create_line(0, self._sweep_y, self.W, self._sweep_y,
                         fill=T.GRID, width=2)
        # ré-afficher les chips d'animation en cours
        for it in self._anim_items:
            it()

    # ---------- animation continue ----------
    def _animate(self):
        self._tick += 1
        self._sweep_y = (self._sweep_y + 6) % self.H
        self._draw_all()
        self.after(60, self._animate)

    def set_status(self, text: str):
        self._status = text

    # ---------- séquence « passer dans la cible » ----------
    def acquire(self, label: str, verdict: str, on_done):
        """Fait voler une menace vers le réticule, la verrouille, puis appelle on_done()."""
        cx, cy = self.W / 2, self.H / 2
        start_x, start_y = self.W - 60, 70
        col = T.THREAT if verdict == "threat" else T.WARNING
        steps = 14
        self.set_status(f"ACQUISITION : {label[:28]}")

        state = {"i": 0}

        def draw_chip():
            i = state["i"]
            if i <= steps:
                t = i / steps
                x = start_x + (cx - start_x) * t
                y = start_y + (cy - start_y) * t
                sz = 10 * (1 - t) + 4
                self.create_rectangle(x - 46, y - 10, x + 46, y + 10,
                                      outline=col, width=1)
                self.create_text(x, y, text=label[:14], font=T.MONO_S, fill=col)
                self.create_line(x, y, cx, cy, fill=T.GRID, width=1)

        self._anim_items.append(draw_chip)

        def step():
            state["i"] += 1
            if state["i"] <= steps:
                self.after(28, step)
            elif state["i"] <= steps + 6:
                # verrouillage : clignotement rouge du réticule
                self._locked = True
                self.set_status(f"CIBLE VERROUILLÉE : {label[:24]}")
                self.after(70, step)
            else:
                self._locked = False
                if draw_chip in self._anim_items:
                    self._anim_items.remove(draw_chip)
                self.set_status("SYSTÈME PRÊT")
                on_done()

        step()
