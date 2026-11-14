#!/usr/bin/env python3
"""
fetch_logos.py — Complète la banque de logos PNG de Bippass à partir des icônes
publiées par les sites eux-mêmes (aucun service tiers).

Sections explorées pour chaque site (les mêmes qu'un « favicon checker ») :
  1. favicon.ico    : https://<domaine>/favicon.ico (+ <link rel="icon" href="...ico">)
  2. link-icon      : balises <link rel="icon"> de la page d'accueil
  3. apple-touch    : <link rel="apple-touch-icon"> + /apple-touch-icon.png
  4. manifest       : icônes du Web App Manifest (<link rel="manifest">,
                      sinon /site.webmanifest et /manifest.json)

Formats acceptés : PNG et ICO uniquement. Le format est vérifié sur le contenu
réel du fichier (signature binaire), pas sur l'extension ni le type MIME annoncé.
SVG, JPEG, WebP, GIF… sont ignorés.

Choix de l'icône — toutes les candidates sont téléchargées puis comparées :
  1. on garde la plus grande taille réelle (côté le plus court, en pixels) ;
  2. à taille égale, priorité : manifest « any » > apple-touch > link-icon
     > favicon.ico > manifest « maskable » (marges et fond imposés) ;
  3. à égalité parfaite, l'icône carrée l'emporte.

Fichier d'entrée : une ligne par site, « domaine » ou « slug domaine » (# = commentaire).
Seul le nom d'hôte est utilisé (google.com/chrome -> google.com).

Usage :
    python fetch_logos.py domains.txt -o logos/
    python fetch_logos.py domains.txt -o logos/ --size 128   # redimensionne en 128x128

Dépendances : Pillow et tqdm (pip install pillow tqdm).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import http.client
import io
import json
import re
import os
import sys
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from PIL import Image
from tqdm import tqdm

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
TIMEOUT = 10          # délai max d'attente réseau par opération
SITE_TIMEOUT = 45     # durée max consacrée à un site (toutes requêtes confondues)
WATCHDOG_GRACE = 30   # au-delà de SITE_TIMEOUT + ce délai, le site est abandonné
MAX_HTML_BYTES = 2_000_000
MAX_ICON_BYTES = 2_000_000
MAX_CANDIDATES = 20  # garde-fou : nombre max d'icônes téléchargées par site

# Priorité à taille égale (plus grand = préféré)
PRIORITY = {
    "manifest": 5,
    "apple-touch": 4,
    "link-icon": 3,
    "favicon.ico": 2,
    "manifest-maskable": 1,
}

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ICO_MAGIC = b"\x00\x00\x01\x00"

# HTTPException couvre IncompleteRead, RemoteDisconnected, BadStatusLine… :
# le serveur a coupé la connexion ou envoyé une réponse malformée.
NET_ERRORS = (HTTPError, URLError, ValueError, TimeoutError, OSError, http.client.HTTPException)
RETRIES = 2  # nouvelles tentatives sur une coupure réseau (pas sur un 404)


# --------------------------------------------------------------------------- #
# Réseau
# --------------------------------------------------------------------------- #
def http_get(url: str, max_bytes: int, deadline: float) -> tuple[str, bytes]:
    """http_get avec nouvelles tentatives sur les coupures de connexion."""
    for attempt in range(RETRIES + 1):
        try:
            return _http_get_once(url, max_bytes, deadline)
        except HTTPError:
            raise  # 404, 403… : le serveur a répondu, réessayer ne changera rien
        except (http.client.HTTPException, ConnectionError, TimeoutError, URLError):
            if attempt == RETRIES or time.monotonic() > deadline:
                raise
            time.sleep(0.5 * (attempt + 1))
    raise AssertionError("inatteignable")


def _http_get_once(url: str, max_bytes: int, deadline: float) -> tuple[str, bytes]:
    """Retourne (url finale après redirections, contenu).

    `deadline` (time.monotonic) borne la durée TOTALE de la requête : sans elle,
    un serveur qui envoie quelques octets toutes les 9 s bloquerait indéfiniment.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("délai du site dépassé")
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urlopen(req, timeout=min(TIMEOUT, remaining)) as resp:
        chunks, total = [], 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("téléchargement trop lent")
            chunk = resp.read(65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("réponse trop volumineuse")
            chunks.append(chunk)
        return resp.geturl(), b"".join(chunks)


# --------------------------------------------------------------------------- #
# Collecte des candidates
# --------------------------------------------------------------------------- #
@dataclass
class Candidate:
    url: str
    section: str  # clé de PRIORITY


class LinkParser(HTMLParser):
    """Récupère les <link rel="icon" | "apple-touch-icon" | "manifest">."""

    def __init__(self) -> None:
        super().__init__()
        self.icons: list[tuple[str, set[str]]] = []
        self.manifests: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "link":
            return
        a = {k.lower(): (v or "").strip() for k, v in attrs}
        rels = set(a.get("rel", "").lower().split())
        href = a.get("href")
        if not href:
            return
        if "manifest" in rels:
            self.manifests.append(href)
        elif rels & {"icon", "apple-touch-icon", "apple-touch-icon-precomposed"}:
            self.icons.append((href, rels))


def manifest_candidates(manifest_url: str, deadline: float) -> list[Candidate]:
    try:
        final_url, raw = http_get(manifest_url, MAX_HTML_BYTES, deadline)
        manifest = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except (*NET_ERRORS, json.JSONDecodeError):
        return []
    out = []
    for icon in manifest.get("icons", []) if isinstance(manifest, dict) else []:
        if not isinstance(icon, dict) or not icon.get("src"):
            continue
        purposes = set(str(icon.get("purpose", "any")).lower().split())
        section = "manifest" if "any" in purposes or not purposes else "manifest-maskable"
        out.append(Candidate(urljoin(final_url, icon["src"]), section))
    return out


def collect_candidates(host: str, deadline: float) -> list[Candidate]:
    base = f"https://{host}/"
    cands: list[Candidate] = []
    manifest_urls: list[str] = []

    # Page d'accueil : balises <link>
    try:
        base, html = http_get(base, MAX_HTML_BYTES, deadline)
        parser = LinkParser()
        parser.feed(html.decode("utf-8", errors="replace"))
        for href, rels in parser.icons:
            url = urljoin(base, href)
            if rels & {"apple-touch-icon", "apple-touch-icon-precomposed"}:
                section = "apple-touch"
            elif url.lower().split("?")[0].endswith(".ico"):
                section = "favicon.ico"
            else:
                section = "link-icon"
            cands.append(Candidate(url, section))
        manifest_urls = [urljoin(base, m) for m in parser.manifests]
    except NET_ERRORS:
        pass

    # Emplacements conventionnels, testés même sans balise
    cands.append(Candidate(urljoin(base, "/apple-touch-icon.png"), "apple-touch"))
    cands.append(Candidate(urljoin(base, "/favicon.ico"), "favicon.ico"))
    if not manifest_urls:
        manifest_urls = [urljoin(base, "/site.webmanifest"), urljoin(base, "/manifest.json")]

    for murl in manifest_urls:
        cands.extend(manifest_candidates(murl, deadline))

    # Dédoublonnage par URL : on garde la section la plus prioritaire
    best: dict[str, Candidate] = {}
    for c in cands:
        if c.url not in best or PRIORITY[c.section] > PRIORITY[best[c.url].section]:
            best[c.url] = c
    return list(best.values())[:MAX_CANDIDATES]


# --------------------------------------------------------------------------- #
# Décodage (PNG / ICO uniquement)
# --------------------------------------------------------------------------- #
def decode_png_or_ico(data: bytes) -> Image.Image | None:
    if data.startswith(PNG_MAGIC):
        fmt = "PNG"
    elif data.startswith(ICO_MAGIC):
        fmt = "ICO"
    else:
        return None  # SVG, JPEG, WebP, page HTML d'erreur…
    try:
        img = Image.open(io.BytesIO(data), formats=[fmt])
        if fmt == "ICO":
            img = img.ico.getimage(max(img.ico.sizes()))  # plus grande image du .ico
        img.load()
    except Exception:
        return None
    return img.convert("RGBA")


# --------------------------------------------------------------------------- #
# Sélection
# --------------------------------------------------------------------------- #
@dataclass
class Picked:
    img: Image.Image
    url: str
    section: str

    @property
    def native(self) -> int:
        return min(self.img.size)

    def rank(self) -> tuple[int, int, int]:
        square = int(self.img.width == self.img.height)
        return (self.native, PRIORITY[self.section], square)


def pick_best(host: str) -> tuple[Picked | None, int]:
    """Retourne (meilleure icône, nombre d'icônes valides trouvées)."""
    deadline = time.monotonic() + SITE_TIMEOUT
    best: Picked | None = None
    valid = 0
    for c in collect_candidates(host, deadline):
        if time.monotonic() > deadline:
            break  # on garde la meilleure icône trouvée jusque-là
        try:
            _, data = http_get(c.url, MAX_ICON_BYTES, deadline)
        except NET_ERRORS:
            continue
        img = decode_png_or_ico(data)
        if img is None:
            continue
        valid += 1
        p = Picked(img, c.url, c.section)
        if best is None or p.rank() > best.rank():
            best = p
    return best, valid


def to_png(img: Image.Image, size: int | None) -> bytes:
    if img.width != img.height:  # centre sur un carré transparent
        side = max(img.size)
        canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        canvas.paste(img, ((side - img.width) // 2, (side - img.height) // 2))
        img = canvas
    if size and img.width != size:
        img = img.resize((size, size), Image.LANCZOS)
    out = io.BytesIO()
    img.save(out, format="PNG", optimize=True)
    return out.getvalue()


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    slug: str
    host: str
    status: str  # "ok", "aucune", "bloqué", "erreur"
    picked: Picked | None = None
    valid: int = 0


def is_valid_png(path: Path) -> bool:
    """Vrai si `path` existe et est un PNG complet (un fichier tronqué renvoie False)."""
    try:
        with Image.open(path, formats=["PNG"]) as img:
            img.load()  # décode tout le fichier : détecte les PNG coupés en cours d'écriture
        return True
    except Exception:
        return False


def write_atomic(path: Path, data: bytes) -> None:
    """Écrit d'abord dans un .tmp puis renomme : jamais de PNG à moitié écrit."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def process(slug: str, host: str, args, started: dict) -> tuple[Result, bytes | None]:
    started[slug] = time.monotonic()  # lu par le chien de garde de main()
    try:
        picked, valid = pick_best(host)
    except Exception as exc:  # une erreur sur un site ne doit pas arrêter les autres
        tqdm.write(f"[erreur] {slug} : {exc!r}", file=sys.stderr)
        return Result(slug, host, "erreur"), None
    if picked is None:
        return Result(slug, host, "aucune"), None
    return Result(slug, host, "ok", picked, valid), to_png(picked.img, args.size)


def host_of(domain: str) -> str:
    return re.sub(r"^https?://", "", domain.strip()).split("/", 1)[0]


def default_slug(host: str) -> str:
    """credit-agricole.fr -> credit-agricole ; impots.gouv.fr -> impots ; www.x.com -> x"""
    parts = host.lower().removeprefix("www.").split(".")
    if len(parts) >= 3 and parts[-2] in {"gouv", "co", "com", "org", "net", "ac"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def read_domains(path: Path) -> list[tuple[str, str]]:
    entries, seen = [], {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        host = host_of(parts[-1])
        slug = parts[0] if len(parts) > 1 else default_slug(host)
        if slug in seen:
            print(f"[doublon] {slug} : {host} ignoré (déjà pris par {seen[slug]})", file=sys.stderr)
            continue
        seen[slug] = host
        entries.append((slug, host))
    return entries


def main() -> int:
    p = argparse.ArgumentParser(description="Récupère les icônes PNG/ICO des sites pour Bippass.")
    p.add_argument("domains", type=Path, help="fichier texte : 'domaine' ou 'slug domaine' par ligne")
    p.add_argument("-o", "--output", type=Path, default=Path("logos"))
    p.add_argument("--credits", type=Path, help="credits.json à compléter (défaut : <output>/credits.json)")
    p.add_argument("--size", type=int, default=None,
                   help="redimensionne en SIZE x SIZE (défaut : taille native)")
    p.add_argument("--force", action="store_true",
                   help="ignorer les PNG déjà présents et tout re-télécharger")
    p.add_argument("-j", "--jobs", type=int, default=8, help="sites traités en parallèle")
    p.add_argument("--only", nargs="+", metavar="SLUG",
                   help="ne traiter que ces slugs (ex. --only netflix deezer)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="n'afficher que la barre et les sites en échec (pas les succès)")
    args = p.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    credits_path = args.credits or args.output / "credits.json"
    credits = json.loads(credits_path.read_text(encoding="utf-8")) if credits_path.exists() else {}

    def save_credits() -> None:
        tmp = credits_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(dict(sorted(credits.items())), indent=4, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp.replace(credits_path)  # écriture atomique : jamais de fichier à moitié écrit

    # Tri AVANT traitement : un logo déjà présent et valide dans logos/ est sauté
    # sans aucune requête réseau ; un PNG absent ou corrompu est (re)téléchargé.
    entries, skipped, broken = [], 0, 0
    for tmp in args.output.glob("*.png.tmp"):  # restes d'une exécution interrompue
        tmp.unlink(missing_ok=True)
    only = set(args.only or [])
    for slug, host in read_domains(args.domains):
        if only and slug not in only:
            continue
        target = args.output / f"{slug}.png"
        if not args.force and target.exists():
            if is_valid_png(target):
                skipped += 1
                continue
            broken += 1
            tqdm.write(f"[abîmé ] {slug:25} {target} corrompu, re-téléchargement")
            target.unlink()
        entries.append((slug, host))

    print(f"{skipped} logo(s) déjà présent(s), ignoré(s) ; "
          f"{broken} corrompu(s) ; {len(entries)} site(s) à traiter.")
    if not entries:
        return 0

    total = len(entries)
    started: dict[str, float] = {}
    results: list[Result] = []
    abandoned = False

    counts: dict[str, int] = {}
    bar = tqdm(total=total, unit="site", dynamic_ncols=True, desc="Logos")

    def record(res: Result, line: str) -> None:
        results.append(res)
        counts[res.status] = counts.get(res.status, 0) + 1
        if not args.quiet or res.status != "ok":
            bar.write(line)  # écrit au-dessus de la barre sans la casser
        bar.set_postfix(counts, refresh=False)
        bar.update(1)

    pool = cf.ThreadPoolExecutor(max_workers=args.jobs)
    futures = {pool.submit(process, s, h, args, started): (s, h) for s, h in entries}
    pending = set(futures)
    try:
        while pending:
            done, pending = cf.wait(pending, timeout=2, return_when=cf.FIRST_COMPLETED)

            for fut in done:
                res, png = fut.result()
                if png is not None:
                    write_atomic(args.output / f"{res.slug}.png", png)
                    credits.setdefault(f"{res.slug}.png", res.picked.url)
                    save_credits()
                if res.picked:
                    pk = res.picked
                    detail = f" {pk.native}px [{pk.section}] ({res.valid} valides) <- {pk.url}"
                else:
                    detail = ""
                record(res, f"[{res.status:6}] {res.slug:25} {res.host}{detail}")

            # Chien de garde : un site qui dépasse largement son délai (ex. DNS figé,
            # que urllib ne sait pas interrompre) est abandonné pour ne pas tout bloquer.
            now = time.monotonic()
            for fut in list(pending):
                slug, host = futures[fut]
                t0 = started.get(slug)
                if t0 is not None and now - t0 > SITE_TIMEOUT + WATCHDOG_GRACE:
                    pending.discard(fut)
                    abandoned = True
                    record(Result(slug, host, "bloqué"), f"[bloqué] {slug:25} {host} (abandonné)")
            bar.refresh()
    except KeyboardInterrupt:
        bar.close()
        print("\nInterrompu : les logos déjà récupérés et credits.json sont conservés.", file=sys.stderr)
        save_credits()
        pool.shutdown(wait=False, cancel_futures=True)
        os._exit(130)

    bar.close()
    save_credits()
    pool.shutdown(wait=not abandoned, cancel_futures=True)

    print("\nRésumé :", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    missing = sorted(r.host for r in results if r.status == "aucune")
    if missing:
        print("Aucune icône PNG/ICO :", " ".join(missing))
    stuck = sorted(r.host for r in results if r.status in {"bloqué", "erreur"})
    if stuck:
        print("Bloqués ou en erreur (relancer pour réessayer) :", " ".join(stuck))
    sys.stdout.flush()
    if abandoned:
        # Des threads restent figés dans un appel réseau : on quitte sans les attendre.
        os._exit(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())