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
└── README.md
```

The bundled file was copied from the supplied lab topology. Linux paths are case-sensitive. The scripts use lowercase `reference` and the filename `ceg_mesh_topo.py`, with the letter `o`. The topology exports `MeshTopo` and registers the Mininet topology name `meshTopo`. Copy or clone the complete repository when setting up another VM.

The supplied topology contains six hosts, six switches, six host attachment links, and 11 switch-to-switch links. Host addresses are `10.0.0.1` through `10.0.0.6`. Links have 40 Mbit/s bandwidth, and switch-link delays supply the routing costs.

## Prerequisites

Mininet, Open vSwitch, Ryu, and Python 3 must be installed in the VM. The launcher uses `sudo` to create network namespaces and configure switches.

Install the additional graph and test utilities on the existing Ubuntu lab image.

```bash
sudo apt-get update
sudo apt-get install -y python3-networkx hping3 tcpdump
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

Unicast forwarding uses Dijkstra shortest paths weighted by link delay. ARP broadcasts and unknown destinations follow a minimum spanning tree, which prevents flooding loops while leaving mesh links available for unicast traffic.

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

Source blocking preserves switches and links for legitimate traffic. The topology is a startup snapshot. Live link-failure discovery and route recomputation are outside the current implementation. Monitoring covers the configured lab host pairs and their source IPs, and IPv6 traffic is discarded.

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
