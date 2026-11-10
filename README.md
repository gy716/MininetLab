# Mininet mesh lab

This lab uses Ryu and OpenFlow 1.3 to route traffic through a six-switch mesh, prevent broadcast loops, detect unusually high source traffic rates, and block anomalous IPv4 sources. Legitimate hosts retain access to the mesh links after a source is blocked.

## Environment and directory layout

The verified environment is the Multipass VM `ca2-part1`, running Ubuntu 20.04, Python 3.8.10, Mininet 2.3.1b4, Open vSwitch 2.13.8, Ryu 4.34, and NetworkX 2.4.

From the Mac terminal, connect to the VM.

```bash
multipass shell ca2-part1
cd ~/MininetLab
```

Run the remaining commands inside Ubuntu. Open a separate VM shell for each terminal mentioned below.

The topology is bundled in this repository. The controller, launcher, and test resolve it relative to their own location.

```text
MininetLab/
├── reference/
│   └── ceg_mesh_topo.py
├── mesh_controller.py
├── run_controller.sh
├── run_topology.sh
├── test_anomaly.py
├── test_dynamic_cost.py
├── test_dynamic_routing.py
├── evaluate_task4.py
├── task4_probe.py
├── plot_task4.py
└── README.md
```

The bundled file was copied from the supplied lab topology. Linux paths are case-sensitive. The scripts use lowercase `reference` and the filename `ceg_mesh_topo.py`, with the letter `o`. The topology exports `MeshTopo` and registers the Mininet topology name `meshTopo`. Copy or clone the complete repository when setting up another VM.

The supplied topology contains six hosts, six switches, six host attachment links, and 11 switch-to-switch links. Host addresses are `10.0.0.1` through `10.0.0.6`. Links have 40 Mbit/s bandwidth, and switch-link delays supply the routing costs.

## Prerequisites

Mininet, Open vSwitch, Ryu, and Python 3 must be installed in the VM. The launcher uses `sudo` to create network namespaces and configure switches.

Install the additional graph and test utilities on the existing Ubuntu lab image.

```bash
sudo apt-get update
sudo apt-get install -y python3-networkx hping3 tcpdump python3-matplotlib
sudo systemctl start openvswitch-switch
```

Check the tools and required topology before starting.

```bash
command -v mn ryu-manager ovs-vsctl ovs-ofctl hping3 tcpdump timeout
mn --version
ovs-vsctl --version
python3 -c 'import networkx; from importlib.metadata import version; print("Ryu", version("ryu")); print("NetworkX", networkx.__version__)'
test -r ~/MininetLab/reference/ceg_mesh_topo.py
sudo ovs-vsctl show
```
# Task 1 
## Topology in MiniEdit
Open a new terminal inside the VM, run
```bash
sudo python -E ~/mininet/examples/miniedit.py
```
Click `File` at the top left corner and open `/MininetLab/reference/ceg_mesh_topo.mn` 

Click `Run`

# Task 2
## Start the controller and topology in command line

In terminal 1, start Ryu and record its output. Keep this terminal open.

```bash
cd ~/MininetLab
set -o pipefail
./run_controller.sh 2>&1 | tee anomaly_controller.log
```

The launcher runs `ryu-manager` with `--observe-links` and listens on TCP port `6653`. Startup logs should report six switches, 11 mesh links, six host ports, and the broadcast tree.

In terminal 2, start the topology.

```bash
cd ~/MininetLab
./run_topology.sh
```

The launcher selects OpenFlow 1.3 and connects to the remote controller at `127.0.0.1:6653`. At the `mininet>` prompt, inspect the network and check connectivity.

```text
nodes
net
pingall
```

A fresh run should report `0% dropped (30/30 received)`. Enter `exit` to stop the topology. Use Ctrl+C in terminal 1 to stop Ryu.

## Run the automated anomaly test

Start a fresh controller using the terminal 1 command above. Run the test with the topology stopped, because the test creates and removes its own network.

In terminal 2, run the following commands.

```bash
cd ~/MininetLab
set -o pipefail
sudo python3 test_anomaly.py 2>&1 | tee anomaly_test.log
```

The test performs these checks in order.

1. Connect all six switches and verify all 30 directed host pairs with `pingall`.
2. Send ten ordinary pings from `h1` to `h2` at one-second intervals to train the baseline.
3. Start continuous legitimate pings from `h3` to `h4`.
4. Generate an ICMP flood from `h1` to `10.0.0.2`, bounded by a 15-second timeout.
5. Require a source-IP drop rule on `s1` within seven seconds.
6. Allow packets already in flight to drain, then capture at `h2` for three seconds. Require zero ICMP echo requests from `h1` while its flood process remains active.
7. Verify that the ingress drop counter increases and that all six switches have the source block.
8. Check all 20 directed pairs among `h2` through `h6` while the flood remains active, plus the continuous legitimate ping.
9. Stop the flood, let the transmit queue drain, and confirm that three ordinary pings from `h1` to `h2` still fail.

Successful completion prints `"passed": true` and exits with status zero. Assertions fail the test when an expected condition is missing. The test stops its child processes and network in its cleanup block.

### Saved evidence

| File | Contents |
| --- | --- |
| `anomaly_controller.log` | Controller startup, accepted baseline samples, anomaly events, and firewall installation messages, recorded by the controller command above |
| `anomaly_test.log` | Full test output, recorded by the test command above |
| `anomaly_test_results.json` | Measurements and assertions' supporting results, written by the test itself |

Each run replaces the corresponding evidence files. The JSON file is created by the privileged test and may be owned by root.

Inspect the results inside the VM.

```bash
cat ~/MininetLab/anomaly_test_results.json
grep -E 'BASELINE|ANOMALY|FIREWALL' ~/MininetLab/anomaly_controller.log
```

### Recorded verification

The completed verification produced these results. Rates and detection times vary between runs.

| Check | Observed result |
| --- | --- |
| Initial connectivity | 30/30 received |
| Normal baseline training | 10/10 received |
| Source EMA before attack | 1.15 packets/s |
| Attack rate at detection | 48,988.01 packets/s |
| Detection threshold | 50 packets/s |
| Source block observed | 1.157 seconds after flood start |
| Attack packets captured at destination after blocking | Zero over three seconds |
| Ingress drop counter | Increased from 67,218 to 270,658 during capture |
| Switches with source block | All six |
| Legitimate host connectivity during flooding | 20/20 received |
| Continuous legitimate ping | 12/12 received |
| Blocked source ping after flood stopped | 0/3 received |

## Manual normal-traffic and flood test

Start a fresh controller and the interactive topology as described above. Enter the following commands at the `mininet>` prompt. The destination address is required for `hping3`.

First establish normal connectivity and the source baseline.

```text
pingall
h1 ping -c 10 -i 1 10.0.0.2
```

Watch terminal 1 for `BASELINE source=10.0.0.1` messages. Then launch a bounded background flood and check a legitimate host pair.

```text
h1 timeout --signal=INT 15s hping3 --icmp --flood 10.0.0.2 > /tmp/mininet-h1-flood.log 2>&1 &
h3 ping -c 5 10.0.0.4
```

The controller should log an `ANOMALY` for `10.0.0.1` followed by six `FIREWALL` messages. Inspect the actual switch rules.

```text
sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0
```

Look for a priority-100 rule matching `nw_src=10.0.0.1` with `actions=drop`. Its `n_packets` counter should increase while the flood continues.

After the 15-second flood ends, check that the block persists and that the other hosts remain connected.

```text
h1 ping -c 3 -W 1 10.0.0.2
py net.ping(hosts=[net.get(name) for name in ('h2', 'h3', 'h4', 'h5', 'h6')], timeout='1')
```

Expect 100% loss for the blocked source and zero loss among the five legitimate hosts. A full `pingall` after blocking includes `h1`, so failures involving that host are expected. The automated test additionally verifies destination packet capture and increasing drop counters during the flood.

## Controller operation and settings

The controller imports the supplied topology in a separate Python process. This avoids the incompatibility between Ryu's asynchronous I/O patches and Mininet's use of `select.poll`. Switch IDs, ports, host IPs, and link delays come from that topology.

IPv4 unicast forwarding uses Dijkstra shortest paths weighted by the dynamic link costs described below. ARP and other L2 forwarding use a stable minimum spanning tree based on original link delays. This prevents broadcast loops while leaving every mesh link available for IPv4 routing.

OpenFlow table 0 applies the firewall and ingress accounting. Table 1 performs forwarding. Accounting flows match IPv4 source/destination pairs at each source host's attachment port, so transit traffic is counted once. ICMP echo replies bypass anomaly accounting to avoid classifying the responding victim as the flood source.

For each active flow, the sampled rate is the increase in its packet counter divided by the increase in its switch-reported flow duration. Rates are aggregated by source. Accepted samples update per-flow and per-source EMAs.

```text
EMA_new = alpha × current_rate + (1 - alpha) × EMA_previous
threshold = max(MIN_THRESHOLD_PPS, ANOMALY_MULTIPLIER × source_EMA_previous)
anomalous when current_source_rate > threshold
```

The comparison uses the previous baseline. An anomalous sample is excluded from EMA updates. Idle samples leave baselines unchanged. A source starts with a provisional baseline of 1 packet/s, and its first accepted sample initializes its learned baseline.

Edit these constants in `MeshController`, then restart the controller to apply changes.

| Constant | Default | Meaning |
| --- | --- | --- |
| `POLL_SECONDS` | `1.0` | Flow-statistics polling interval |
| `EMA_ALPHA` | `0.2` | Weight assigned to the newest accepted sample |
| `ANOMALY_MULTIPLIER` | `5.0` | Source EMA multiplier |
| `MIN_THRESHOLD_PPS` | `50.0` | Minimum anomaly threshold in packets/s |

A detected source receives a priority-100 IPv4 drop rule on every connected switch. The PacketIn handler also rejects queued packets from blocked sources. Blocks cover all IPv4 protocols for that source and remain active for the controller session. They are reapplied when a switch reconnects during that session.

Source blocking preserves switches and links for legitimate traffic. The topology is a startup snapshot. New and active IPv4 flows use current link costs, with hysteresis and a cooldown for active migrations. Live physical-link failure handling remains outside the current implementation. Monitoring covers the configured lab host pairs and their source IPs, and IPv6 traffic is discarded.

## Dynamic link costs

For each switch-to-switch link, the controller implements the supplied cost model.

```text
C_ij(t) = C0_ij + LOAD_COST_ALPHA × U_ij(t) + ANOMALY_COST_BETA × A_ij(t)
U_ij(t) = min(1, max(TX_rate_i_to_j, TX_rate_j_to_i) / capacity_ij)
TX_rate = 8 × change_in_tx_bytes / change_in_port_duration
```

### Original costs and units

`C0` is read directly from the link's preset delay in `reference/ceg_mesh_topo.py`. The cost is expressed in millisecond-based units. Dynamic penalties influence route choice while the link's configured delay and bandwidth continue to govern packet transmission in Mininet.

| Link | Original cost |
| --- | --- |
| s1–s2 | 5 |
| s2–s3 | 10 |
| s4–s5 | 15 |
| s5–s6 | 20 |
| s1–s4 | 8 |
| s2–s5 | 12 |
| s3–s6 | 7 |
| s1–s5 | 18 |
| s2–s4 | 6 |
| s2–s6 | 14 |
| s3–s5 | 9 |

Bandwidth is read from each link's `bw` value and converted from Mbit/s to bit/s. Every supplied mesh link has a reference capacity of 40,000,000 bit/s. Host attachment links are excluded from the routing graph.

### Load measurement

Every polling interval, OpenFlow port-statistics requests collect transmit-byte counters from both ends of each mesh link. Rates use counter deltas and the switch-reported port duration. Receiving a packet at the opposite endpoint is the same transmission, so the calculation uses the two TX directions. Because the graph represents an undirected full-duplex link, its cost reflects the busier direction. For example, two simultaneous 20 Mbit/s directions give 50% utilization on a 40 Mbit/s link.

The first sample establishes a reference with zero estimated load. Counter resets restart that reference. Missing replies retain the last known rate, and unsupported counters are ignored. Short measurement bursts above the configured capacity are capped at 100% utilization. Each endpoint updates when its reply arrives, so the two direction samples can have slightly different collection times.

`base_cost` is stored independently from the live `weight`. Every update starts from that original value, which prevents repeated updates from accumulating penalties.

### Anomaly attribution and lifetime

When the existing EMA detector flags a source, the controller looks at that source's positive ingress-flow deltas in the current statistics window. Each corresponding installed source/destination route identifies the switch links used by that traffic. Those links receive `A=1`. This is an inference from source counters and installed paths.

The binary anomaly penalty lasts 30 seconds from detection. Multiple detections affecting the same edge extend its expiry. Expiry returns `A` to zero, while measured load continues to contribute to cost. The source-IP firewall block lasts for the controller session independently of this temporary link penalty.

This targets links associated with observed anomalous traffic. An inactive source/destination pair contributes no affected links for that window. If the active pair has no installed route record, the controller has no path to attribute to that pair.

### Routing decisions and flow consistency

A routing flow is an IPv4 source/destination pair. The first packet selects a complete shortest path from the live costs. The controller caches that path and installs rules matching the source IP, destination IP, and expected ingress port.

Every polling cycle also reevaluates active legitimate flows. Migration requires a cost improvement of at least both 2 cost units and 10% of the current path cost. A five-second cooldown limits repeated migrations as load changes. Blocked sources and destinations are excluded from active migration.

A worker installs the candidate path from destination to source and waits for each switch's OpenFlow barrier acknowledgement before proceeding upstream. This ensures a new downstream suffix exists before traffic is directed into it. Rules match the preceding ingress port, allowing old-only path segments to coexist with the new path. After the new source rule is acknowledged, the controller commits the new cached path and retains old-only rules for one second to drain in-flight packets. Cookie-specific cleanup then removes those retired rules. A missing acknowledgement triggers restoration of the former path. Waiting happens outside the main event handler so barrier replies can be processed.

Separate forwarding-counter polls refresh activity, including ICMP echo replies. Ten seconds of observed inactivity still removes an idle route. Firewall and source-accounting entries are preserved during route updates. The broadcast tree remains stable. Physical topology is still a startup snapshot.

### Routing parameters and example

| Constant | Default | Meaning |
| --- | --- | --- |
| `LOAD_COST_ALPHA` | `30.0` | Cost added at full link utilization |
| `ANOMALY_COST_BETA` | `50.0` | Additional cost while an edge is anomaly-affected |
| `ANOMALY_HOLD_SECONDS` | `30.0` | Temporary edge-penalty lifetime |
| `ROUTE_IDLE_SECONDS` | `10.0` | Observed inactivity before route cleanup |
| `REROUTE_MIN_IMPROVEMENT` | `2.0` | Minimum absolute cost improvement |
| `REROUTE_MIN_FRACTION` | `0.10` | Minimum relative cost improvement |
| `REROUTE_COOLDOWN_SECONDS` | `5.0` | Minimum interval between active migrations |
| `BARRIER_TIMEOUT_SECONDS` | `2.0` | Acknowledgement timeout per switch |
| `OLD_PATH_DRAIN_SECONDS` | `1.0` | Retention of old-only path entries after migration |

The routing coefficient `LOAD_COST_ALPHA` is separate from the detector's `EMA_ALPHA=0.2`. Restart the controller after changing these constants.

For s1–s2, the original cost is 5. At 20 Mbit/s, utilization is 0.5 and the cost becomes `5 + 30 × 0.5 = 20`. The alternative s1–s4–s2 costs `8 + 6 = 14` when idle, so a new flow can prefer that alternative. If s1–s2 is also anomaly-affected, its cost becomes `20 + 50 = 70`. When traffic and the temporary penalty clear, its cost returns toward 5.

### Verify dynamic routing

Run the deterministic checks inside the VM. They exercise original delays, utilization units, full-duplex measurements, counter resets, utilization capping, cached-path consistency, new route selection, anomaly expiry, acknowledged active migration, cooldown, and rollback.

```bash
cd ~/MininetLab
python3 -m unittest -v test_dynamic_cost.py
```

For the live load test, start a fresh controller in terminal 1 and run the following command in terminal 2 with the topology stopped.

```bash
cd ~/MininetLab
sudo python3 test_dynamic_routing.py
```

The live test creates the network and sends a bounded, paced echo-reply stream from h2 to h1. Echo replies are exempt from the existing source anomaly detector, which lets this test isolate the load term. They still contribute to the mesh port counters. The test verifies successful h1-to-h3 pings, inspects s1's forwarding rule for the alternative first hop through s4, stops the stream, waits for route inactivity expiry, and verifies recovery of the first hop through s2. It cleans up its network and traffic process.

The earlier subsequent-flow implementation was verified on 10 November 2026 with three deterministic checks and two live tests. Under load, s1–s2 reached about 30 cost units and a new h1-to-h3 flow selected s1–s4–s2–s3 at cost 24. After traffic stopped and the route expired, the flow selected s1–s2–s3 at cost 15. Both three-packet ping checks had zero loss. The anomaly regression also preserved all 20 legitimate directed host pairs, blocked the attacker, and raised the affected link's cost before the temporary penalty expired.

Restart the controller and run `sudo python3 test_anomaly.py` to repeat the complete source-blocking and legitimate-connectivity regression test.

Controller logs make each decision inspectable.

- `LINK_COST` records the base cost, measured rate in bit/s, utilization, anomaly flag, and resulting cost. Changes smaller than 0.1 cost units are omitted from the log while still updating the graph.
- `ANOMALY_LINKS` records the affected source, inferred edges, and penalty lifetime.
- `ROUTE` records the source, destination, selected switch sequence, and total cost at selection time.
- `REROUTE` records the committed active migration, old/new paths, and old/new costs.
- `REROUTE_FAILED` and `OPENFLOW_ERROR` identify update failures for diagnosis.

## Task 4 integrated evaluation

Stop the previous Mininet network and controller, then run the three independent cases inside the VM.

```bash
cd ~/MininetLab
python3 -m unittest -v test_dynamic_cost.py
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -u evaluate_task4.py
sudo python3 plot_task4.py
```

The evaluation starts and stops a fresh controller and topology for each case. It measures a continuous h1-to-h6 stream for 65 seconds, with a bounded ICMP flood from 15 to 27 seconds. Cases A, B, and C target s2–s3 using h2–h3, s2–s6 using h2–h6, and s5–s6 using h5–h6 respectively.

The legitimate UDP stream offers 0.3072 Mbps using 32 packets/s of 1200 bytes, plus ordinary one-second pings. This defined offered load stays below the 50 packets/s anomaly floor during initial baseline learning. Received sequence numbers determine packet loss, and received payload bytes determine throughput. One-second normalized costs use current affected-link cost divided by its original delay cost.

The experiment pins only the attack pair to its assigned direct link through the optional MININET_ROUTE_PINS environment setting. This ensures case C loads s5–s6, whose cost of 20 exceeds the natural s5–s3–s6 path cost of 16. Normal controller runs have no pins. The legitimate flow remains adaptive in every case. MININET_TELEMETRY_FILE optionally enables one-second JSONL state snapshots for the measurement process.

All three measured cases passed on 10 November 2026. Cases A and C kept h1–h6 on s1–s2–s6. Case B changed the still-active flow to s1–s2–s3–s6 at approximately 18 seconds and returned to s1–s2–s6 at approximately 47 seconds. All measured legitimate UDP packets were received at this offered load. Every case verified the attack source block on all six switches, zero attack packets at the destination during the post-block capture, rising drop counters, and all 20 legitimate post-attack ping pairs.

The results are documented in [the Task 4 report](results/task4/TASK4_REPORT.md). Plots and CSV measurements are in results/task4. Raw controller logs, sent/received datagrams, telemetry, capture output, and flow-table snapshots are in its case_a, case_b, and case_c subdirectories. Flow-table snapshots independently confirm the reported paths at 10, 20, and 60 seconds. These are single trials at the stated offered load.

Each evaluation replaces its own case files. The After period includes the residual anomaly penalty. The report additionally isolates a Recovered period beginning two seconds after penalty expiry. Source-IP firewall blocks persist independently until the per-case controller is stopped.

## Reset and troubleshooting

For a fresh experiment, enter `exit` in the interactive Mininet session or let the automated test finish. Stop Ryu with Ctrl+C, then start the controller and topology again. This resets learned baselines and the blocked-source set, and switch initialization replaces the prior flow rules.

| Symptom | Check |
| --- | --- |
| Topology file cannot be read | Verify that `reference/ceg_mesh_topo.py` exists inside this repository |
| Switches cannot connect | Start Ryu first, check port 6653, and retain the launcher's remote-controller and OpenFlow 1.3 settings |
| Port 6653 is already occupied | Run `sudo ss -ltnp 'sport = :6653'` and stop the identified previous lab controller |
| Fresh test immediately fails connectivity involving h1 | Restart Ryu to clear the previous experiment's source block |
| Test cannot find a required executable | Recheck the prerequisites and tool paths inside the VM |
| Interfaces remain after an interrupted Mininet run | Close active lab sessions, then run `sudo mn -c` before restarting. This cleanup affects Mininet resources across the VM |
| Capture exits with status 124 in test results | This is the expected timeout when no matching attack packet arrives during the capture window |

Inspect controller connectivity from the Mininet prompt.

```text
sh ovs-vsctl --columns=target,is_connected list Controller
```
