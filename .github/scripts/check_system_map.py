import html, json, pathlib, re, sys

SRC = pathlib.Path("docs/semafide.architecture.json")
MAP = pathlib.Path("docs/semafide-system-map.html")

for path in (SRC, MAP):
    if not path.exists():
        sys.exit(f"{path} is missing; this check has nothing to assert")

source = json.loads(SRC.read_text(encoding="utf-8"))
page = MAP.read_text(encoding="utf-8")

svg = re.search(r"<svg\b.*?</svg>", page, re.DOTALL)
if svg is None:
    sys.exit(f"no <svg> element in {MAP}; this check has nothing to assert")
svg = svg.group(0)

components = source.get("components", [])
connections = source.get("connections", [])
boundaries = source.get("boundaries", [])
cards = source.get("cards", [])
if not (components and connections and cards):
    sys.exit(f"{SRC} declares no components, connections or cards; "
             "this check has nothing to assert")

# Every comparison below is an equality, never a substring. A status tag is the
# highest-stakes field in this file and UNBUILT contains BUILT, so a substring
# test would report green on the one edit that most misleads a reader.
drift = []

want = "0 0 {} {}".format(*source["meta"]["viewBox"])
got = re.search(r'<svg[^>]*viewBox="([^"]+)"', svg)
if got is None or got.group(1) != want:
    drift.append(f"viewBox: source says {want!r}, map says "
                 f"{got and got.group(1)!r}")

# The map renders each node's full description into one <title>, in the order
# label · sublabel · enclosing boundary · tag. Rebuilding that string from the
# source and comparing it whole asserts the label, the responsibility, which
# boundary encloses the node, and the build status in a single equality.
encloses = {member: boundary["label"]
            for boundary in boundaries for member in boundary["wraps"]}

for component in components:
    node = re.search(r'<g id="node-%s"(.*?)(?=<g id="node-|</svg>)'
                     % re.escape(component["id"]), svg, re.DOTALL)
    if node is None:
        drift.append(f"{component['id']}: no node in the map")
        continue
    body = node.group(1)

    box = re.search(r'<rect x="(-?\d+)" y="(-?\d+)" '
                    r'width="(\d+)" height="(\d+)"', body)
    drawn = [int(n) for n in box.groups()] if box else None
    authored = list(component["pos"]) + list(component["size"])
    if drawn != authored:
        drift.append(f"{component['id']}: source places it at {authored}, "
                     f"map draws it at {drawn}")

    kind = re.search(r'data-node-kind="([^"]*)"', body)
    if kind is None or kind.group(1) != component["type"]:
        drift.append(f"{component['id']}: source types it "
                     f"{component['type']!r}, map says "
                     f"{kind and kind.group(1)!r}")

    described = [component["label"], component["sublabel"],
                 encloses.get(component["id"], "Architecture component")]
    if component.get("tag"):
        described.append(component["tag"])
    described = " · ".join(described)
    title = re.search(r"<title>(.*?)</title>", body, re.DOTALL)
    title = html.unescape(title.group(1)) if title else None
    if title != described:
        drift.append(f"{component['id']}: source describes it {described!r}, "
                     f"map labels it {title!r}")

drawn = set(re.findall(r'data-edge-id="([^"]+)"', svg))
authored = {connection["id"] for connection in connections}
for missing in sorted(authored - drawn):
    drift.append(f"{missing}: in the source, not drawn in the map")
for extra in sorted(drawn - authored):
    drift.append(f"{extra}: drawn in the map, not in the source")

for connection in connections:
    edge = re.search(r'<[a-z]+[^>]*data-edge-id="%s"[^>]*>'
                     % re.escape(connection["id"]), svg)
    if edge is None:
        continue
    edge = edge.group(0)
    for attribute, field in (("data-edge-from", "from"),
                             ("data-edge-to", "to"),
                             ("data-edge-label", "label")):
        want = connection.get(field)
        got = re.search(r'%s="([^"]*)"' % attribute, edge)
        got = html.unescape(got.group(1)) if got else None
        if want != got:
            drift.append(f"{connection['id']}: source says {field}={want!r}, "
                         f"map says {got!r}")
    want = "a-" + connection.get("variant", "default")
    got = re.search(r'class="([^"]*)"', edge)
    if got is None or got.group(1) != want:
        drift.append(f"{connection['id']}: source draws it {want!r}, "
                     f"map draws it {got and got.group(1)!r}")

labelled = {html.unescape(text).strip()
            for text in re.findall(r">([^<>]+)<", svg)}
for boundary in boundaries:
    if boundary["label"] not in labelled:
        drift.append(f"boundary {boundary['label']!r} is not drawn in the map")

# The proposition cards carry the claim discipline: what each property does not
# establish, and which claims are hypotheses. They are compared in order and in
# full, so a trimmed qualifier fails rather than passing as a prefix.
rendered = []
for card in re.finditer(r'<div class="card">\s*<div class="card-header">\s*'
                        r'<div class="card-dot ([a-z]+)"></div>\s*'
                        r"<h3>(.*?)</h3>\s*</div>\s*<ul>(.*?)</ul>",
                        page[page.index("</svg>"):], re.DOTALL):
    items = [html.unescape(item).replace("•", "", 1).strip()
             for item in re.findall(r"<li>(.*?)</li>", card.group(3),
                                    re.DOTALL)]
    rendered.append((card.group(1), html.unescape(card.group(2)), items))

authored = [(card["dot"], card["title"], card["items"]) for card in cards]
if len(rendered) != len(authored):
    drift.append(f"source declares {len(authored)} cards, map renders "
                 f"{len(rendered)}")
for want, got in zip(authored, rendered):
    if want != got:
        drift.append(f"card {want[1]!r} differs between the source and the map")
        if want[0] != got[0]:
            drift.append(f"  dot: source {want[0]!r}, map {got[0]!r}")
        if want[1] != got[1]:
            drift.append(f"  title: source {want[1]!r}, map {got[1]!r}")
        for line in sorted(set(want[2]) - set(got[2])):
            drift.append(f"  in the source, not in the map: {line!r}")
        for line in sorted(set(got[2]) - set(want[2])):
            drift.append(f"  in the map, not in the source: {line!r}")

views = re.search(r'<script id="archify-guided-views-data" '
                  r'type="application/json">(.*?)</script>', page, re.DOTALL)
if views is None:
    drift.append("the map carries no guided-view data")
elif json.loads(views.group(1)) != source["meta"]["views"]:
    drift.append("guided views differ between the source and the map")

if drift:
    print("::error::README.md says docs/semafide-system-map.html is generated "
          "from docs/semafide.architecture.json. They no longer agree. "
          "Re-export the map from the source, or correct the source.")
    for item in drift:
        print(f"  {item}")
    sys.exit(1)

print(f"map agrees with its source on {len(components)} components, "
      f"{len(connections)} connections, {len(boundaries)} boundaries and "
      f"{sum(len(card['items']) for card in cards)} card lines")
