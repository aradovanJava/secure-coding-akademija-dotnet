#!/usr/bin/env python3
"""
CI izvještaj za VulnShop Akademija (.NET).

  ci_report.py build <restore.log> <build.log>
      Iz logova izvlači greške kompilacije/restorea i ispisuje ih kao GitHub anotacije (::error).

  ci_report.py tests <TestResults-dir> <branch>
      Parsira TRX datoteke i ispisuje SAŽETAK PO VJEŽBI kao ::notice anotaciju, npr.
        Lab01: RANJIVO (2/2 testova pada)   ili   Lab01: ISPRAVLJENO (2/2 prolazi)
      te popis neuspjelih testova (s prvim retkom poruke) kao zasebne anotacije.
      Sažetak se zapisuje i u $GITHUB_STEP_SUMMARY.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
LABS = [f"Lab{i:02d}" for i in range(1, 16)]


def esc(text: str) -> str:
    """Kodiranje poruke za GitHub workflow naredbe (%, CR, LF)."""
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def esc_prop(text: str) -> str:
    return esc(text).replace(":", "%3A").replace(",", "%2C")


def annotate(level: str, title: str, lines, chunk=40):
    """Ispisuje anotaciju; dugačke popise dijeli u više anotacija (ograničenje veličine)."""
    lines = list(lines)
    if not lines:
        return
    for start in range(0, len(lines), chunk):
        part = lines[start:start + chunk]
        suffix = f" ({start // chunk + 1})" if len(lines) > chunk else ""
        print(f"::{level} title={esc_prop(title + suffix)}::{esc(chr(10).join(part))}")


def summary(md: str):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md + "\n")


def build_report(logs):
    pattern = re.compile(r"^(?P<file>[^\s(][^(]*?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>[A-Z]+\d+): (?P<msg>.*?)(?: \[.*\])?$")
    generic = re.compile(r"error (?P<code>(?:NU|MSB|NETSDK|CS)\d+)\s*:?\s*(?P<msg>.*)")
    seen, lines = set(), []
    root = os.getcwd().rstrip("/") + "/"
    for log in logs:
        if not os.path.exists(log):
            continue
        for raw in open(log, encoding="utf-8", errors="replace"):
            raw = raw.strip()
            m = pattern.match(raw)
            if m:
                f = m.group("file").replace(root, "")
                key = (f, m.group("line"), m.group("code"), m.group("msg"))
                if key in seen:
                    continue
                seen.add(key)
                lines.append(f"{f}:{m.group('line')}:{m.group('col')} {m.group('code')} {m.group('msg')}")
                if len(seen) <= 10:
                    print(f"::error file={f},line={m.group('line')},col={m.group('col')}::{esc(m.group('code') + ' ' + m.group('msg'))}")
                continue
            g = generic.search(raw)
            if g:
                key = ("", "", g.group("code"), g.group("msg"))
                if key not in seen:
                    seen.add(key)
                    lines.append(f"{g.group('code')} {g.group('msg')}"[:400])
    if not lines:
        lines = ["Build nije uspio, ali greške nisu prepoznate – pogledajte log koraka Build."]
    annotate("error", "Greške builda (sve)", lines)
    summary("## Greške builda\n\n```\n" + "\n".join(lines[:200]) + "\n```")


def parse_trx(path):
    tree = ET.parse(path)
    root = tree.getroot()
    classes = {}
    for ut in root.findall(".//t:TestDefinitions/t:UnitTest", NS):
        tm = ut.find("t:TestMethod", NS)
        classes[ut.get("id")] = tm.get("className") if tm is not None else ""
    results = []
    for r in root.findall(".//t:Results/t:UnitTestResult", NS):
        name = r.get("testName", "")
        cls = classes.get(r.get("testId"), "")
        m = re.search(r"Lab(\d{2})", cls + " " + name)
        lab = f"Lab{m.group(1)}" if m else "Ostalo"
        msg_el = r.find(".//t:Output/t:ErrorInfo/t:Message", NS)
        msg = (msg_el.text or "").strip() if msg_el is not None else ""
        results.append({"lab": lab, "name": name, "outcome": r.get("outcome", ""), "message": msg})
    return results


def tests_report(directory, branch):
    files = {os.path.basename(p): p for p in glob.glob(os.path.join(directory, "**", "*.trx"), recursive=True)}
    functional = parse_trx(files["functional.trx"]) if "functional.trx" in files else []
    security = parse_trx(files["security.trx"]) if "security.trx" in files else []

    def short(msg):
        first = next((l.strip() for l in msg.splitlines() if l.strip()), "")
        return first[:300]

    # --- funkcionalni ---
    f_fail = [r for r in functional if r["outcome"] != "Passed"]
    f_line = (f"Funkcionalni testovi: {len(functional) - len(f_fail)}/{len(functional)} prolazi"
              if functional else "Funkcionalni testovi: nema rezultata (build ili pokretanje nije uspjelo)")

    # --- sigurnosni, po vježbi ---
    lines = [f"Grana: {branch}", f_line, ""]
    md = ["## Sažetak po vježbi", "", f"Grana: `{branch}`  ", f_line, "",
          "| Vježba | Stanje | Sigurnosni testovi |", "|---|---|---|"]
    not_failing_on_main = []
    for lab in LABS:
        rs = [r for r in security if r["lab"] == lab]
        failed = [r for r in rs if r["outcome"] != "Passed"]
        if not rs:
            state, detail = "NEMA TESTOVA", "0 testova"
        elif failed:
            state, detail = "RANJIVO", f"{len(failed)}/{len(rs)} testova pada"
        else:
            state, detail = "ISPRAVLJENO", f"{len(rs)}/{len(rs)} prolazi"
            not_failing_on_main.append(lab)
        lines.append(f"{lab}: {state} ({detail})")
        md.append(f"| {lab} | {state} | {detail} |")

    annotate("notice", "Lab sažetak", lines, chunk=60)
    summary("\n".join(md))

    if f_fail:
        annotate("error", "Neuspjeli FUNKCIONALNI testovi",
                 [f"{r['name']}: {short(r['message'])}" for r in f_fail], chunk=20)

    s_fail = [r for r in security if r["outcome"] != "Passed"]
    if s_fail:
        level = "error" if branch == "rjesenja" else "notice"
        title = ("Neuspjeli SIGURNOSNI testovi" if branch == "rjesenja"
                 else "Pali sigurnosni testovi (očekivano na ranjivoj grani)")
        annotate(level, title, [f"{r['name']}: {short(r['message'])}" for r in s_fail], chunk=20)

    if branch == "main" and security and not_failing_on_main:
        annotate("warning", "Vježbe bez palog sigurnosnog testa na main",
                 [f"{lab}: nijedan sigurnosni test ne pada – ranjivost nije dokazana" for lab in not_failing_on_main])


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "build":
        build_report(sys.argv[2:])
    elif mode == "tests":
        tests_report(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    else:
        sys.exit(f"Nepoznat način rada: {mode}")
