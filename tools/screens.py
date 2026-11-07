#!/usr/bin/env python3
"""The screens of a VM test run, as pictures: what the console, the SSH sessions and the phone
showed in each scenario, for a person to look at.

    tools/screens.py .local/runs/<run>            # every machine's screens/ in the run
    tools/screens.py .local/runs/<run>/arch       # one machine

tools/vmtest.py keeps, per scenario, screens/NN-scenario/ in the machine's run directory: the
console as it came from the serial port (console.ansi), each session's transcript (session-*.log:
control and the other commands; boot-*.log: the code screen over SSH) and the phone's
screenshots (phone-*.png, tools/phone-vm-test.py). This turns each text into an SVG of a terminal
- colours, bold, carriage returns and cursor moves applied as a terminal would - and writes
index.html beside the run's screens: per machine and scenario, every picture. It checks nothing.

The standard library alone; the pictures open in any browser.
"""

import argparse
import glob
import html
import os
import re
import sys

COLS = 160  # the width a line wraps at, as on a wide terminal
ROWS = 50   # the viewport a cursor position counts from

PALETTE = ["#1d1f21", "#cc6666", "#b5bd68", "#f0c674", "#81a2be", "#b294bb", "#8abeb7", "#c5c8c6"]
BRIGHT = ["#666666", "#ff7b7b", "#d2e27f", "#ffe08a", "#9fc3e7", "#d4b4dd", "#a3e4dc", "#ffffff"]
FG, BG = "#c5c8c6", "#1d1f21"

ESC = re.compile(rb"\x1b(?:\[([0-9;?]*)([A-Za-z@`])|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][A-Za-z0-9]|[=>78DEHMc])")


class Terminal:
    """A terminal that keeps every line it ever showed: the cells' characters and styles."""

    def __init__(self):
        self.lines = [[]]
        self.row = self.col = 0
        self.style = (None, False)  # colour, bold
        self.saved = (0, 0)

    def top(self):
        return max(0, len(self.lines) - ROWS)

    def line(self):
        while self.row >= len(self.lines):
            self.lines.append([])
        return self.lines[self.row]

    def put(self, ch):
        if self.col >= COLS:
            self.row, self.col = self.row + 1, 0
        ln = self.line()
        while len(ln) < self.col:
            ln.append((" ", (None, False)))
        cell = (ch, self.style)
        if self.col < len(ln):
            ln[self.col] = cell
        else:
            ln.append(cell)
        self.col += 1

    def feed(self, data):
        pos = 0
        while pos < len(data):
            m = ESC.search(data, pos)
            end = m.start() if m else len(data)
            self.text(data[pos:end].decode("utf-8", "replace"))
            if not m:
                break
            if m.group(2):
                self.csi(m.group(1).decode(), m.group(2).decode())
            elif m.group(0) == b"\x1b7":
                self.saved = (self.row, self.col)
            elif m.group(0) == b"\x1b8":
                self.row, self.col = self.saved
            pos = m.end()

    def text(self, s):
        for ch in s:
            if ch == "\n":
                self.row += 1
                self.col = 0  # serial consoles and transcripts: a newline begins the line
                self.line()
            elif ch == "\r":
                self.col = 0
            elif ch == "\b":
                self.col = max(0, self.col - 1)
            elif ch == "\t":
                self.col = (self.col // 8 + 1) * 8
            elif ch == "\x07" or ord(ch) < 32:
                continue
            else:
                self.put(ch)

    def csi(self, params, cmd):
        nums = [int(p) if p.isdigit() else 0 for p in params.lstrip("?").split(";")] if params else []
        n = nums[0] if nums and nums[0] else 1
        if cmd == "m":
            self.sgr(nums or [0])
        elif cmd == "A":
            self.row = max(self.top(), self.row - n)
        elif cmd == "B":
            self.row += n
        elif cmd == "C":
            self.col += n
        elif cmd == "D":
            self.col = max(0, self.col - n)
        elif cmd == "G":
            self.col = n - 1
        elif cmd in "Hf":
            r = nums[0] if nums and nums[0] else 1
            c = nums[1] if len(nums) > 1 and nums[1] else 1
            self.row, self.col = self.top() + r - 1, c - 1
        elif cmd == "K":
            ln = self.line()
            mode = nums[0] if nums else 0
            if mode == 0:
                del ln[self.col:]
            elif mode == 1:
                for i in range(min(self.col + 1, len(ln))):
                    ln[i] = (" ", (None, False))
            else:
                ln.clear()
        elif cmd == "J":
            mode = nums[0] if nums else 0
            if mode in (2, 3):
                # A cleared screen: what was on it stays above, the new one begins below.
                self.lines.extend([] for _ in range(1))
                self.row, self.col = len(self.lines) - 1, 0
            elif mode == 0:
                del self.line()[self.col:]
                del self.lines[self.row + 1:]

    def sgr(self, nums):
        colour, bold = self.style
        i = 0
        while i < len(nums):
            v = nums[i]
            if v == 0:
                colour, bold = None, False
            elif v == 1:
                bold = True
            elif v == 22:
                bold = False
            elif 30 <= v <= 37:
                colour = v - 30
            elif 90 <= v <= 97:
                colour = v - 90 + 8
            elif v == 39:
                colour = None
            elif v in (38, 48) and i + 1 < len(nums):
                i += 2 if nums[i + 1] == 5 else 4  # 256 colours, true colour: not drawn
            i += 1
        self.style = (colour, bold)


def colour_of(style):
    colour, bold = style
    if colour is None:
        return "#ffffff" if bold else FG
    if colour >= 8:
        return BRIGHT[colour - 8]
    return BRIGHT[colour] if bold else PALETTE[colour]


def svg(lines, title):
    """The lines as a terminal's picture."""
    while lines and not lines[-1]:
        lines.pop()
    cw, lh, pad = 7.8, 17, 12
    width = int(pad * 2 + cw * max([len(l) for l in lines] + [40]))
    height = int(pad * 2 + 24 + lh * max(1, len(lines)))
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
           f"<title>{html.escape(title)}</title>",
           f'<rect width="100%" height="100%" rx="8" fill="{BG}"/>',
           '<circle cx="16" cy="14" r="5" fill="#ff5f56"/><circle cx="32" cy="14" r="5" fill="#ffbd2e"/><circle cx="48" cy="14" r="5" fill="#27c93f"/>',
           f'<text x="{width / 2}" y="18" fill="#888" font-family="sans-serif" font-size="11" text-anchor="middle">{html.escape(title)}</text>',
           '<g font-family="DejaVu Sans Mono, Menlo, Consolas, monospace" font-size="13" xml:space="preserve">']
    for i, ln in enumerate(lines):
        if not ln:
            continue
        y = pad + 24 + lh * i + 12
        spans, run, cur = [], "", None
        for ch, st in ln:
            if st != cur and run:
                spans.append((run, cur))
                run = ""
            cur = st
            run += ch
        if run:
            spans.append((run, cur))
        parts = []
        for text, st in spans:
            weight = ' font-weight="bold"' if st and st[1] else ""
            parts.append(f'<tspan fill="{colour_of(st or (None, False))}"{weight}>{html.escape(text)}</tspan>')
        out.append(f'<text x="{pad}" y="{y}">{"".join(parts)}</text>')
    out.append("</g></svg>")
    return "\n".join(out)


def render(path, title):
    t = Terminal()
    with open(path, "rb") as f:
        t.feed(f.read())
    lines = [[(ch, st) for ch, st in ln] for ln in t.lines]
    out = os.path.splitext(path)[0] + ".svg"
    with open(out, "w") as f:
        f.write(svg(lines, title))
    return out


KINDS = (("console.ansi", "the console"), ("session-*.log", "a session"), ("boot-*.log", "the code screen over SSH"))


def machine_dirs(root):
    if os.path.isdir(os.path.join(root, "screens")):
        return [root]
    return sorted(d for d in glob.glob(os.path.join(root, "*")) if os.path.isdir(os.path.join(d, "screens")))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run", help="a run directory of tools/vmtest.py (or of one machine in it)")
    a = p.parse_args()
    root = os.path.abspath(a.run)
    machines = machine_dirs(root)
    if not machines:
        print(f"screens: no screens/ under {root}: a run of tools/vmtest.py keeps them", file=sys.stderr)
        return 2
    body, count = [], 0
    for m in machines:
        name = os.path.basename(m)
        body.append(f"<h2>{html.escape(name)}</h2>")
        for sc in sorted(glob.glob(os.path.join(m, "screens", "*"))):
            if not os.path.isdir(sc):
                continue
            scenario = re.sub(r"^\d+-", "", os.path.basename(sc))
            items = []
            for pattern, what in KINDS:
                for f in sorted(glob.glob(os.path.join(sc, pattern))):
                    if os.path.getsize(f) == 0:
                        continue
                    label = f"{name} - {scenario} - {what}: {os.path.basename(f)}"
                    items.append((os.path.relpath(render(f, label), root), label))
            for f in sorted(glob.glob(os.path.join(sc, "*.png"))):
                items.append((os.path.relpath(f, root), f"{name} - {scenario} - the phone: {os.path.basename(f)}"))
            if not items:
                continue
            body.append(f'<h3 id="{html.escape(name)}-{html.escape(scenario)}">{html.escape(scenario)}</h3>')
            for src, label in items:
                count += 1
                cls = "phone" if src.endswith(".png") else "term"
                body.append(f'<figure class="{cls}"><a href="{html.escape(src)}"><img src="{html.escape(src)}" alt="{html.escape(label)}" loading="lazy"></a>'
                            f"<figcaption>{html.escape(label)}</figcaption></figure>")
    index = os.path.join(root, "screens.html")
    with open(index, "w") as f:
        f.write("<!DOCTYPE html><meta charset=utf-8><title>tpm2-kira screens</title>"
                "<style>body{font-family:sans-serif;background:#f4f4f4;margin:16px}figure{margin:12px 0}"
                "img{max-width:100%;border:1px solid #ccc;background:#1d1f21}figure.phone img{max-width:360px}"
                "figcaption{font-size:12px;color:#555}</style>"
                f"<h1>tpm2-kira: the screens of {html.escape(os.path.basename(root))}</h1>" + "\n".join(body))
    print(f"screens: {count} pictures, {index}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
