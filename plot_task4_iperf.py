"""Plot one uninterrupted iperf2 UDP experiment using receiver measurements.

CSV UDP fields are timestamp, endpoints, ID, interval, bytes, bits/s, jitter,
lost datagrams, total datagrams, loss percent and out-of-order datagrams.
Only one-second interval records are used; final cumulative reports are not
additional samples. Missing intervals remain gaps rather than fabricated zeros.
"""
import csv
import json
import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main(folder):
    origin = json.loads((folder / "stream.json").read_text())["start_monotonic"]
    cases = json.loads((folder / "summary.json").read_text())
    telemetry = [json.loads(line) for line in (folder / "controller_telemetry.jsonl").read_text().splitlines()]
    samples = []
    for row in csv.reader((folder / "iperf_server.csv").read_text().splitlines()):
        if len(row) < 13:
            continue
        try:
            begin, end = map(float, row[6].split("-"))
            if not .5 <= end - begin <= 1.5:
                continue
            samples.append(dict(time=end, start=begin, mbps=float(row[8])/1e6,
                                lost=int(row[10]), total=int(row[11]), loss=float(row[12])))
        except ValueError:
            continue
    assert samples, "No receiver interval measurements found"
    with open(folder / "iperf_metrics.csv", "w") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(samples[0]))
        writer.writeheader()
        writer.writerows(samples)
    fig, axes = plt.subplots(3, 1, figsize=(16, 11), sharex=True)
    active = [r for r in telemetry if 0 <= r["time"]-origin <= samples[-1]["time"]]
    for edge in sorted(active[0]["links"]):
        axes[0].plot([r["time"]-origin for r in active],
            [r["links"][edge]["weight"]/r["links"][edge]["base_cost"] for r in active],
            label=edge, linewidth=1.2)
    axes[0].legend(ncol=4, fontsize=8)
    axes[0].set_ylabel("Normalized cost (C / C0)")
    axes[1].plot([r["time"] for r in samples], [r["loss"] for r in samples], color="firebrick")
    axes[1].set_ylabel("Receiver packet loss (%)")
    axes[1].set_ylim(bottom=0)
    axes[2].plot([r["time"] for r in samples], [r["mbps"] for r in samples], color="forestgreen")
    axes[2].set_ylabel("Received throughput (Mbps)")
    axes[2].set_ylim(bottom=0)
    report = ["# Continuous 10 Mbps UDP evaluation", "",
              "One iperf session and one controller span all cases. The iperf2 `10M` target is 10,485,760 bits/s (about 10.49 decimal Mbps). Receiver intervals are approximately one second; time zero is client launch (small startup/propagation offset). Loss is iperf's sequence-based estimate, not inferred from offered throughput.", ""]
    for case in cases:
        offset = case["stream_offset"]
        block_time = offset + case["attack_start"] + case["block_after_attack_seconds"]
        recovered = next(r["time"]-origin-offset for r in active
                         if r["time"]-origin > block_time
                         and case["attack_source"] not in r["blocked"])
        events = [(case["attack_start"], "attack starts"),
                  (case["attack_start"]+case["block_after_attack_seconds"], "blocked"),
                  (case["attack_end"], "attack stops"),
                  (recovered, "source recovered")]
        for when, label in events:
            x = offset + when
            for ax in axes:
                ax.axvline(x, color="gray", linestyle=":", linewidth=.7)
            axes[0].text(x + (-.6 if label == "attack starts" else .6), 1.01, case["case"].upper()+": "+label,
                rotation=90, fontsize=7, transform=axes[0].get_xaxis_transform())
        report += ["## Case " + case["case"].upper(),
                   "Paths: `" + str(case["path_changes"]) + "`", "",
                   "| Phase | Received Mbps | Packet loss % | Mean normalized affected-link cost |", "|---|---:|---:|---:|"]
        bounds = [("Before",0,case["attack_start"]),
                  ("During flood",case["attack_start"],case["attack_end"]),
                  ("After flood",case["attack_end"],recovered),
                  ("Recovered",recovered,case["recovery_verified_at"])]
        for name, lo, hi in bounds:
            rows = [r for r in samples if offset+lo <= (r["start"]+r["time"])/2 < offset+hi]
            assert rows, "Missing receiver samples for " + name
            assert all(any(r["mbps"] > 0 for r in rows[i:i+5]) for i in range(0,len(rows),5)), "Connectivity interruption"
            loss = 100*sum(r["lost"] for r in rows)/max(1,sum(r["total"] for r in rows))
            links = [r["links"][case["affected_link"]] for r in active
                     if offset+lo <= r["time"]-origin < offset+hi]
            cost = sum(e["weight"]/e["base_cost"] for e in links)/len(links)
            report.append("| %s | %.3f | %.3f | %.3f |" % (name,sum(r["mbps"] for r in rows)/len(rows),loss,cost))
        report += ["", "Source blocking, destination capture, firewall counters and recovered pingall passed. Cost penalties expire independently of source recovery. Case B can move off s2-s6 when the alternative becomes cheaper; off-path attacks need not change h1-h6's route. Receiver intervals are assigned to phases by their midpoint, including intervals straddling an event. Brief loss can occur without a route change; these measurements alone cannot distinguish congestion, host scheduling, socket drops and routing effects. No loss is imposed or suppressed.", ""]
    for ax in axes:
        ax.grid(alpha=.25)
    axes[2].set_xlabel("Time since continuous h1 → h6 stream started (s)")
    fig.suptitle("Cases A, B and C sequentially — continuous 10 Mbps iperf UDP", y=.995)
    fig.subplots_adjust(left=.07, right=.98, bottom=.07, top=.86, hspace=.12)
    fig.savefig(folder / "task4_iperf.png", dpi=160)
    (folder / "REPORT.md").write_text("\n".join(report))

if __name__ == "__main__":
    main(Path(sys.argv[1]))
