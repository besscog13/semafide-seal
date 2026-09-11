import html, json, pathlib, re, sys

SRC = pathlib.Path("docs/semafide.architecture.json")
MAP = pathlib.Path("docs/semafide-system-map.html")
README = pathlib.Path("README.md")

for path in (SRC, MAP):
    if not path.exists():
        sys.exit(f"{path} is missing; this check has nothing to assert")

readme = README.read_text(encoding="utf-8") if README.exists() else ""
# There is no exporter in this repository. A generation claim would be
# the defect this check exists to refuse.
if re.search(r"generated from.{0,80}semafide\\.architecture\\.json", readme, re.I | re.S):
    sys.exit("README.md claims the map is generated from the JSON. "
             "No exporter lives in this repository. State agreement, not generation.")

source = json.loads(SRC.read_text(encoding="utf-8"))
page = MAP.read_text(encoding="utf-8")

svg = re.search(r"<svg\\b.*?</svg>", page, re.DOTALL)
if svg is None:
    sys.exit(f"no <svg> element in {MAP}; this check has nothing to assert")
svg = svg.group(0)
