# Continuous 10 Mbps UDP evaluation

One iperf session and one controller span all cases. The iperf2 `10M` target is 10,485,760 bits/s (about 10.49 decimal Mbps). Receiver intervals are approximately one second; time zero is client launch (small startup/propagation offset). Loss is iperf's sequence-based estimate, not inferred from offered throughput.

## Case A
Paths: `[{'time': 0.0007241690036607906, 'path': [1, 2, 6]}]`

| Phase | Received Mbps | Packet loss % | Mean normalized affected-link cost |
|---|---:|---:|---:|
| Before | 10.486 | 0.000 | 1.000 |
| During flood | 10.486 | 0.000 | 2.680 |
| After flood | 10.486 | 0.000 | 2.059 |
| Recovered | 10.488 | 0.000 | 1.000 |

Source blocking, destination capture, firewall counters and recovered pingall passed. Cost penalties expire independently of source recovery. Case B can move off s2-s6 when the alternative becomes cheaper; off-path attacks need not change h1-h6's route. Receiver intervals are assigned to phases by their midpoint, including intervals straddling an event. Brief loss can occur without a route change; these measurements alone cannot distinguish congestion, host scheduling, socket drops and routing effects. No loss is imposed or suppressed.

## Case B
Paths: `[{'time': 0.001854021000326611, 'path': [1, 2, 6]}, {'time': 20.000998111994704, 'path': [1, 2, 3, 6]}, {'time': 48.00089399299759, 'path': [1, 2, 6]}]`

| Phase | Received Mbps | Packet loss % | Mean normalized affected-link cost |
|---|---:|---:|---:|
| Before | 10.486 | 0.000 | 1.077 |
| During flood | 10.436 | 0.374 | 2.233 |
| After flood | 10.489 | 0.000 | 1.744 |
| Recovered | 10.482 | 0.000 | 1.077 |

Source blocking, destination capture, firewall counters and recovered pingall passed. Cost penalties expire independently of source recovery. Case B can move off s2-s6 when the alternative becomes cheaper; off-path attacks need not change h1-h6's route. Receiver intervals are assigned to phases by their midpoint, including intervals straddling an event. Brief loss can occur without a route change; these measurements alone cannot distinguish congestion, host scheduling, socket drops and routing effects. No loss is imposed or suppressed.

## Case C
Paths: `[{'time': 0.0016083109949249774, 'path': [1, 2, 6]}]`

| Phase | Received Mbps | Packet loss % | Mean normalized affected-link cost |
|---|---:|---:|---:|
| Before | 10.483 | 0.022 | 1.000 |
| During flood | 10.486 | 0.000 | 1.679 |
| After flood | 10.486 | 0.000 | 1.588 |
| Recovered | 10.486 | 0.000 | 1.000 |

Source blocking, destination capture, firewall counters and recovered pingall passed. Cost penalties expire independently of source recovery. Case B can move off s2-s6 when the alternative becomes cheaper; off-path attacks need not change h1-h6's route. Receiver intervals are assigned to phases by their midpoint, including intervals straddling an event. Brief loss can occur without a route change; these measurements alone cannot distinguish congestion, host scheduling, socket drops and routing effects. No loss is imposed or suppressed.
