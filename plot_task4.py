"""Plot Task 4's measured data and generate CSV files plus an evidence report."""
import bisect
import csv
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from test_anomaly import module

ROOT = Path(__file__).resolve().parent / "results/task4"
OFFERED = 0.3072
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.alpha": 0.22})


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def prepare(case):
    folder = ROOT / ("case_" + case)
    summary = json.loads((folder / "summary.json").read_text())
    assert summary["passed"]
    # Validate the controller's reported paths against actual switch entries.
    topo = module.MeshTopo()
    for tick, path in {10: [1, 2, 6], 20: [1, 2, 3, 6] if case == "b" else [1, 2, 6],
                       60: [1, 2, 6]}.items():
        snapshot = json.loads((folder / ("flows_%02d.json" % tick)).read_text())
        for index, node in enumerate(path):
            switch = "s" + str(node)
            previous = "h1" if index == 0 else "s" + str(path[index - 1])
            following = "h6" if index == len(path) - 1 else "s" + str(path[index + 1])
            ingress, output = topo.port(switch, previous)[0], topo.port(switch, following)[0]
            assert any("table=1" in line and "priority=20" in line
                and "nw_src=10.0.0.1,nw_dst=10.0.0.6" in line
                and "in_port=%d," % ingress in line
                and "actions=output:%d" % output in line
                for line in snapshot[switch].splitlines()), (case, tick, switch)
    log = (folder / "controller.log").read_text()
    assert "REROUTE_FAILED" not in log and "OPENFLOW_ERROR" not in log
    start, duration = summary["start_monotonic"], summary["duration"]
    sent = read(folder / "sent.jsonl")
    received = {row["seq"]: row for row in read(folder / "received.jsonl")}
    telemetry = read(folder / "telemetry.jsonl")
    stamps = [row["time"] for row in telemetry]

    def measure(begin, end):
        tx = [row for row in sent if start + begin <= row["time"] < start + end]
        matched = sum(row["seq"] in received for row in tx)
        rx_bytes = sum(row["bytes"] for row in received.values()
                       if start + begin <= row["time"] < start + end)
        return dict(transmitted=len(tx), lost=len(tx) - matched,
                    loss_pct=100 * (len(tx) - matched) / len(tx) if tx else 0,
                    throughput_mbps=rx_bytes * 8 / 1e6 / (end - begin))
    rows = []
    for second in range(duration):
        snapshot = telemetry[max(0, bisect.bisect_right(stamps, start + second + 0.5) - 1)]
        link = snapshot["links"][summary["affected_link"]]
        metric = measure(second, second + 1)
        metric.update(time_s=second + 0.5, link_cost=link["weight"],
            normalized_cost=link["weight"] / link["base_cost"],
            link_rate_mbps=link["rate_bps"] / 1e6, anomaly=int(link["anomaly"]),
            path=snapshot["routes"].get("10.0.0.1,10.0.0.6", {}).get("path", []))
        rows.append(metric)
    with open(ROOT / ("case_" + case + "_metrics.csv"), "w") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary["phases"] = {name: measure(begin, end) for name, begin, end in [
        ("Before", 0, 15), ("During", 15, 27), ("After", 27, duration),
        ("Recovered", summary["penalty_end"] + 2, duration)]}
    summary["maximum_normalized_cost"] = max(row["normalized_cost"] for row in rows)
    summary["maximum_link_cost"] = max(row["link_cost"] for row in rows)
    summary["base_link_cost"] = telemetry[0]["links"][summary["affected_link"]]["base_cost"]
    summary["initial_link_cost"] = rows[0]["link_cost"]
    for name, begin, end in [("Before", 0, 15), ("During", 15, 27), ("After", 27, duration),
                             ("Recovered", summary["penalty_end"] + 2, duration)]:
        selected = [row for row in rows if begin <= row["time_s"] < end]
        summary["phases"][name]["mean_link_cost"] = sum(row["link_cost"] for row in selected) / len(selected)
        summary["phases"][name]["mean_normalized_cost"] = sum(row["normalized_cost"] for row in selected) / len(selected)
    summary["rule_snapshots_verified"] = True
    return summary, rows


def draw(axes, summary, rows):
    x = [row["time_s"] for row in rows]
    for ax, field, label, color in zip(axes,
            ["normalized_cost", "loss_pct", "throughput_mbps"],
            ["Normalized link cost  C(t) / C0", "Packet loss (%)", "Received throughput (Mbps)"],
            ["#2864a0", "#b73543", "#148273"]):
        ax.plot(x, [row[field] for row in rows], color=color, lw=1.8,
                drawstyle="steps-mid" if field != "throughput_mbps" else "default")
        ax.axvspan(15, 27, color="#f3ba73", alpha=0.24)
        ax.axvline(summary["penalty_end"], color="#8b5db4", linestyle="--", lw=1.2)
        for change in summary["path_changes"][1:]:
            ax.axvline(change["time"], color="#444444", linestyle=":", lw=0.9)
        ax.set_ylabel(label)
        ax.set_xlim(0, summary["duration"])
    axes[0].axhline(1, color="#888888", lw=0.8, linestyle=":")
    axes[0].set_ylim(0.7, max(2, summary["maximum_normalized_cost"] * 1.12))
    axes[1].set_ylim(0, max(5, max(row["loss_pct"] for row in rows) * 1.2))
    axes[2].axhline(OFFERED, color="#777777", linestyle=":", lw=1)
    axes[2].set_ylim(0, max(0.36, max(row["throughput_mbps"] for row in rows) * 1.1))
    axes[2].set_xlabel("Time from measurement start (s)")


data = [prepare(case) for case in "abc"]
legend = [Patch(facecolor="#f3ba73", alpha=0.4, label="Flood generator active"),
          Line2D([0], [0], color="#8b5db4", linestyle="--", label="Anomaly penalty expires"),
          Line2D([0], [0], color="#444444", linestyle=":", label="h1–h6 path change")]
for summary, rows in data:
    fig, axes = plt.subplots(3, 1, figsize=(11, 9), sharex=True)
    draw(axes, summary, rows)
    fig.suptitle("Case %s · %s" % (summary["case"].upper(),
        summary["affected_link"].replace("-", "–")), fontsize=17, fontweight="bold", y=0.98)
    fig.legend(handles=legend, loc="upper center", bbox_to_anchor=(0.5, 0.945), ncol=3, fontsize=9)
    paths = "  |  ".join("%.0fs  %s" % (row["time"], " → ".join("s%d" % n for n in row["path"]))
                         for row in summary["path_changes"])
    fig.text(0.5, 0.015, "Measured h1–h6 paths    " + paths, ha="center", fontsize=9)
    fig.tight_layout(rect=(0.02, 0.04, 0.99, 0.90), h_pad=1.2)
    fig.savefig(ROOT / ("case_" + summary["case"] + "_plots.png"), dpi=170)
    plt.close(fig)
fig, grid = plt.subplots(3, 3, figsize=(17, 10), sharex=True)
for column, (summary, rows) in enumerate(data):
    draw(grid[:, column], summary, rows)
    grid[0, column].set_title("Case %s · %s" % (
        summary["case"].upper(), summary["affected_link"].replace("-", "–")),
        fontsize=14, fontweight="bold")
# Shared metric scales support comparisons across the three cases.
for ax in grid[0, :]:
    ax.set_ylim(0.7, max(s["maximum_normalized_cost"] for s, _ in data) * 1.12)
for ax in grid[2, :]:
    ax.set_ylim(0, max(0.36, max(row["throughput_mbps"] for _, rows in data for row in rows) * 1.1))
fig.suptitle("Task 4 · Active-flow rerouting under three anomaly cases",
             fontsize=19, fontweight="bold", y=0.99)
fig.legend(handles=legend, loc="upper center", bbox_to_anchor=(0.5, 0.955), ncol=3, fontsize=10)
fig.tight_layout(rect=(0.01, 0.01, 0.99, 0.92), w_pad=2)
fig.savefig(ROOT / "task4_overview.png", dpi=170)
plt.close(fig)
(ROOT / "metrics_summary.json").write_text(json.dumps([s for s, _ in data], indent=2))

report = [
"# Task 4 evaluation", "", "Measured on 10 November 2026 in Multipass VM ca2-part1.", "",
"## Method", "",
"Three independent 65-second trials used fresh controllers and the original topology. Each began with 30/30 "
"successful ping checks. The continuous h1-to-h6 UDP stream offered 0.3072 Mbps using 32 datagrams/s of 1200 "
"bytes each. A concurrent one-second ping checked bidirectional reachability. This legitimate rate stays below "
"the 50 packets/s detector floor during baseline initialization.", "",
"The flood generator ran from 15 to 27 seconds. Measurement continued until 65 seconds to observe the "
"30-second anomaly penalty expire and the active route recover. The After phase includes the remaining "
"penalty interval. Recovered starts two seconds after the measured penalty expiry.", "",
"Only each attack pair was pinned to the assigned direct link. Case C requires this constraint because "
"s5–s3–s6 costs 16, below the direct s5–s6 cost of 20. h1–h6 remained fully adaptive in every case. "
"Original link delays and bandwidths were preserved.", "",
"## Active-route design", "",
"The cost is C0 + 30 × utilization + 50 × anomaly. Utilization uses the busier TX direction divided by "
"40 Mbit/s, capped at 1. The anomaly term lasts 30 seconds after detection. The source firewall block persists "
"for the controller session.", "",
"Routes are reconsidered once per second. Migration requires improvement of at least both 2 cost units "
"and 10%, with a five-second cooldown. Installation proceeds destination-to-source, waiting for each switch's "
"OpenFlow barrier acknowledgement. Rules match ingress port and IP pair. Old-only entries drain for one second "
"before cookie-specific removal. Failed acknowledgements trigger restoration of the previous path. "
"The ARP tree stays stable.", "",
"## Measurements", "",
"- Normalized cost is affected-link cost divided by original delay. Its base value is 1, and it can exceed 1.",
"- Loss uses transmitted UDP sequence numbers grouped by one-second send windows. Later arrivals within the "
"capture are credited to their original send window.",
"- Throughput uses unique UDP payload bytes received by h6 in one-second receive windows. Offered rate is 0.3072 Mbps.",
"- Path changes are sampled approximately once per second. Actual flow-table snapshots independently verify "
"paths at 10, 20, and 60 seconds.", "",
"![Three-case overview](task4_overview.png)", ""]
for summary, rows in data:
    case = summary["case"]
    report += ["## Case " + case.upper(), "",
        "Attack on **%s**, from **%s** to **%s**." %
        (summary["affected_link"], summary["attack_source"], summary["attack_target"]), "",
        "Original delay cost is **%.1f**. The first measured affected-link cost is **%.3f**. "
        "The initial h1–h6 path is **s1 → s2 → s6**, whose original delay sum is **19**." %
        (summary["base_link_cost"], summary["initial_link_cost"]), "",
        "| Phase | Mean link cost | Mean normalized cost | Loss (%) | Received throughput (Mbps) |",
        "| --- | ---: | ---: | ---: | ---: |"]
    for phase, m in summary["phases"].items():
        report.append("| %s | %.3f | %.3f | %.3f | %.4f |" %
            (phase, m["mean_link_cost"], m["mean_normalized_cost"], m["loss_pct"], m["throughput_mbps"]))
    report += ["", "Blocking was observed **%.2f seconds** after flood start. The sampled peak link cost "
        "was **%.3f**, or **%.3f times its original value**. Penalty expiry was approximately **%.2f seconds**." %
        (summary["block_after_attack_seconds"], summary["maximum_link_cost"],
         summary["maximum_normalized_cost"], summary["penalty_end"]), "",
        "Recorded h1–h6 paths", ""]
    report += ["- %.1fs — %s" % (row["time"], " → ".join("s%d" % node for node in row["path"]))
               for row in summary["path_changes"]]
    report += ["", ("The affected s2–s6 link was on the initial route. The active flow moved through s2–s3–s6 "
        "as the penalty made that alternative cheaper, then returned to the direct s2–s6 segment after recovery."
        if case == "b" else "The affected link was outside h1–h6's s1–s2–s6 route. That route stayed preferable, "
        "so the controller correctly retained it."), "",
        "All six switches installed the source block. A three-second destination capture observed zero "
        "post-block attack packets while the flood remained active. The ingress drop counter increased "
        "from **%d to %d**. All 20 legitimate post-attack ping checks passed, and ordinary pings from "
        "the blocked source failed after the flood stopped." % (summary["drops_before"], summary["drops_after"]), "",
        "![Case %s plots](case_%s_plots.png)" % (case.upper(), case), ""]
report += ["## Interpretation and limits", "",
"The firewall stops sustained attack forwarding shortly after detection. High link load is consequently a "
"short burst even while the generator continues until 27 seconds. Costs remain elevated during the anomaly "
"hold, then return toward the original values. A link carrying the continuing legitimate stream retains a "
"small load surcharge.", "",
"Loss and throughput are measured at the receiver. Per-second throughput fluctuations can reflect packet "
"timing and VM scheduling. Shared destination links and CPU load can affect delivery even when the targeted "
"switch link is outside h1–h6's path. These trials establish continuity at the stated offered load. "
"Maximum TCP capacity was not measured. One trial per case provides no statistical confidence interval.", "",
"## Reproduce", "", "With the previous network and controller stopped, run inside the VM.", "",
chr(96)*3 + "bash", "cd ~/MininetLab", "python3 -m unittest -v test_dynamic_cost.py",
"sudo env PYTHONDONTWRITEBYTECODE=1 python3 -u evaluate_task4.py",
"sudo python3 plot_task4.py", chr(96)*3, "",
"Raw datagram logs, telemetry, captures, summaries, and flow snapshots are in results/task4/case_a, case_b, "
"and case_c. The CSV files contain one-second measurements. Each run replaces these case outputs.", ""]
(ROOT / "TASK4_REPORT.md").write_text("\n".join(report))
print(json.dumps([dict(case=s["case"], phases=s["phases"], paths=s["path_changes"],
                       peak=s["maximum_normalized_cost"]) for s, _ in data], indent=2))

