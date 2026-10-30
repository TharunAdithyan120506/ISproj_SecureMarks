"""Run every security and performance analysis and write the evidence.

    python -m cryptolab.report            # about a minute
    python -m cryptolab.report --full     # adds 4 MB / 10 MB payloads and more trials

Outputs in cryptolab/out/: report.json (everything), one CSV per table, and
the PNG figures; the figures are also copied to docs/figures/ (lab_*.png) for
the README.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from cryptolab import figures, hashlab, image, perf, samples, schemes, signlab, store, text  # noqa: E402
from cryptolab.serialize import public  # noqa: E402

OUT = ROOT / "cryptolab" / "out"
DOCS = ROOT / "docs" / "figures"
console = Console(highlight=False, width=None if sys.stdout.isatty() else 140)


def _csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    cols = [c for c in rows[0] if not c.startswith("_") and not isinstance(rows[0][c], (list, dict))]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def run(full: bool = False) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()
    out: dict = {"cpu": platform.processor() or platform.machine(), "python": platform.python_version(),
                 "mode": "full" if full else "quick", "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    figs: list[Path] = []

    console.rule("[bold]Text encryption")
    pt = text.DEFAULT_TEXT.encode()
    comp = text.compare_schemes(pt, trials=96 if full else 48)
    out["text_compare"] = comp
    _csv(OUT / "text_compare.csv", comp)
    for r in comp:
        console.print(f"  {r['scheme']:<16} avalanche {r['avalanche_bit_pct']:6.2f} % bits / {r['avalanche_char_pct']:6.2f} % bytes"
                      f"   key-sens {r['key_sens_bit_pct']:6.2f} %   H {r['ciphertext_entropy_4k']:.4f}")
    out["text_diffusion"] = {n: text.diffusion_map(n, samples=3) for n in schemes.NAMES}
    sizes = perf.TEXT_SIZES_FULL if full else perf.TEXT_SIZES
    sweep = perf.sweep_schemes(schemes.NAMES, sizes)
    out["text_perf"] = sweep
    _csv(OUT / "text_perf.csv", sweep)
    figs += [figures.text_avalanche(comp, OUT / "text_avalanche.png"),
             figures.text_perf(sweep, OUT / "text_encrypt_time.png"),
             figures.text_perf(sweep, OUT / "text_decrypt_time.png", "decrypt_ms",
                               "Decryption time against plaintext length"),
             figures.text_perf(sweep, OUT / "text_throughput.png", "encrypt_MBps",
                               "Encryption throughput against plaintext length", "MB/s")]

    console.rule("[bold]Image encryption")
    photo = samples.photo(256)
    main = image.analyze(photo, schemes.PRIMARY)
    out["image_primary"] = public(main)
    console.print(f"  {schemes.PRIMARY}: NPCR {main['npcr']:.4f} %  UACI {main['uaci']:.4f} %  entropy "
                  f"{main['entropy_cipher']['all']:.4f}  corr H {main['corr_cipher']['horizontal']['mean']:+.4f}  "
                  f"PSNR {main['psnr_plain_cipher']} dB  verdict {sum(main['verdict'].values())}/{len(main['verdict'])}")
    comp_img = image.compare(photo)
    out["image_compare"] = public(comp_img)
    _csv(OUT / "image_compare.csv", comp_img)
    logo = samples.logo(256)
    logo_rows = image.compare(logo, ["AES-256-ECB", "AES-256-CBC", schemes.PRIMARY])
    out["image_perf"] = image.sweep_sizes(photo, schemes.NAMES, (64, 128, 256, 512) if not full else (64, 128, 256, 512, 1024))
    _csv(OUT / "image_perf.csv", out["image_perf"])
    a = main["_arrays"]
    figs += [
        figures.image_gallery({"plain": a["plain"], "R": image.channel_view(a["plain"], 0),
                               "G": image.channel_view(a["plain"], 1), "B": image.channel_view(a["plain"], 2),
                               "cipher (GCM-SIV)": a["cipher"], "decrypted": a["decrypted"]},
                              OUT / "image_gallery.png", "Image encryption: RGB channels, cipher image, decryption"),
        figures.image_gallery({"plain": logo, **{r["scheme"].replace("AES-256-", ""): r["_cipher"] for r in logo_rows}},
                              OUT / "image_ecb_leak.png", "Why ECB is insecure: identical blocks stay identical"),
        figures.histograms(main["hist_plain"], main["hist_cipher"], OUT / "image_histograms.png"),
        figures.correlation_scatter(main["scatter_plain"], main["scatter_cipher"], main["corr_plain"],
                                    main["corr_cipher"], OUT / "image_correlation.png"),
        figures.image_scheme_metrics(comp_img, OUT / "image_npcr_uaci.png", main["npcr_ideal"], main["uaci_ideal"]),
        figures.image_perf(out["image_perf"], OUT / "image_perf.png"),
    ]

    console.rule("[bold]Hashing")
    out["hash_digests"] = hashlab.digest_all(pt)
    out["hash_avalanche"] = [hashlab.avalanche(n, pt, 128 if full else 64) for n in hashlab.NAMES]
    res = hashlab.resistance("SHA-256", preimage_bits=(8, 10, 12, 14, 16, 18) if full else (8, 10, 12, 14, 16),
                             collision_bits=(8, 12, 16, 20, 24, 28, 32) if full else (8, 12, 16, 20, 24, 28),
                             trials=12 if full else 6)
    out["hash_resistance"] = res
    for k in ("preimage", "second_preimage", "collision"):
        console.print(f"  {res[k]['kind']:<17} " + "  ".join(f"k={r['bits']}: 2^{r['log2_mean']:.1f} (2^{r['log2_theory']:.1f})"
                                                           for r in res[k]["rows"]))
    out["hash_extrapolation"] = {n: hashlab.extrapolate(n) for n in hashlab.CRYPTO}
    out["hash_lab5"] = hashlab.lab5_dataset(100)
    out["hash_djb2_collision"] = hashlab.djb2_collision()
    out["hash_perf"] = hashlab.sweep()
    _csv(OUT / "hash_perf.csv", out["hash_perf"])
    figs += [figures.hash_resistance(res, OUT / "hash_resistance.png"),
             figures.hash_perf(out["hash_perf"], OUT / "hash_throughput.png")]

    console.rule("[bold]Digital signatures")
    sig = signlab.compare(300 if full else 100)
    out["signatures"] = sig
    _csv(OUT / "signatures.csv", [{**r, "sign_median_ms": r["sign_ms"]["median"], "verify_median_ms": r["verify_ms"]["median"],
                                   "keygen_median_ms": r["keygen_ms"]["median"]} for r in sig])
    for r in sig:
        console.print(f"  {r['algorithm']:<13} sign {r['sign_ms']['median']:.4f} ms  verify {r['verify_ms']['median']:.4f} ms"
                      f"  keygen {r['keygen_ms']['median']:.2f} ms  sig {r['signature_bytes']} B")
        store.save("signature", r["algorithm"], {"source": "report", "runs": r["runs"]},
                   {"sign_ms": r["sign_ms"]["median"], "verify_ms": r["verify_ms"]["median"],
                    "keygen_ms": r["keygen_ms"]["median"], "signature_bytes": r["signature_bytes"]})
    figs.append(figures.signature_times(sig, OUT / "signature_times.png"))

    out["seconds"] = round(time.perf_counter() - t_start, 1)
    out["figures"] = [p.name for p in figs]
    (OUT / "report.json").write_text(json.dumps(public(out), indent=1, default=str), encoding="utf-8")
    DOCS.mkdir(parents=True, exist_ok=True)
    for p in figs:
        shutil.copyfile(p, DOCS / f"lab_{p.name}")
    console.print(f"\n[bold green]done[/] in {out['seconds']} s → {OUT} ({len(figs)} figures, also in docs/figures/lab_*.png)")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--full", action="store_true", help="larger payloads and more trials")
    run(ap.parse_args().full)


if __name__ == "__main__":
    main()
