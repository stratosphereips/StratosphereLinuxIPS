# Stress Testing Slips - Baseline Report

## Scope and artifacts
This report covers the baseline stress-testing experiments in
`/home/alya/Desktop/StratosphereLinuxIPS/output/stress_testing/baseline` and
summarizes their plots and metrics. All referenced plots are copied into
`/home/alya/Desktop/StratosphereLinuxIPS/docs/images/immune/c3`.

### Failure states (definitions)
#### Soft Break FPS
**Definition:** Throughput at which Slips shows significantly reduced performance (for example, when input reading speed diverges from profiler throughput, or latency increases sharply).
Practical signals in baseline data: Persistent gap between input flows/min and profiler flows/min, sustained high latency (p95/p99), or noticeable latency spikes.

#### Hard Break FPS
**Definition:** Complete system crash or failure of the Slips process.
Practical signals in baseline data: Missing or abruptly truncated outputs, crashes visible in logs, or plots/metrics not being produced.


## Baseline experiments overview
<div style="width:100%; overflow-x:auto;">

| Experiment name | Input avg (flows/min) | Input peak (flows/min) | Profiler avg (flows/min) | Avg gap (input vs profiler) | Latency avg (seconds) | Latency p95 | Latency p99 | Max latency | Summary (plots + metrics) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| CTU-Mixed-Capture-1 | 10,836.2 | 23,404 | 10,426.6 | 3.78% | 0.0879 | 0.0 | 0.0 | 32.0 | Profiler throughput tracks input tightly; near-zero latency with rare spikes; no soft-break signals. |
| CTU-Mixed-Capture-2 | 7,607.5 | 15,215 | 7,425.0 | 2.40% | 2.1829 | 23.0 | 29.0 | 32.0 | Short capture window; small throughput gap; heavier latency tail but average stays low. |
| CTU-Normal-18 | 11,688.3 | 21,277 | 8,925.0 | 23.64% | 1.5410 | 14.6 | 30.0 | 52.0 | Largest throughput gap; latency spikes higher but not sustained; closest to soft-break among baselines. |

</div>

## Baseline plots and commentary

### CTU-Mixed-Capture-1

**Flows/min**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-1/plots/flows_per_minute_for_all_profilers" width="640">

Input peaks at 23,404 flows per min.

**Throughput**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-1/plots/throughput_plot" width="640">

**Latency**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-1/plots/latency_plot" width="640">

Near-zero latency with rare spikes to 32s.

### CTU-Mixed-Capture-2

**Flows/min**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-2/plots/flows_per_minute_for_all_profilers" width="640">

**Throughput**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-2/plots/throughput_plot" width="640">

**Latency**
<img src="../../output/stress_testing/baseline/CTU-Mixed-Capture-2/plots/latency_plot" width="640">

max 32s

### CTU-Normal-18

**Flows/min**
<img src="../../output/stress_testing/baseline/CTU-Normal-18/plots/flows_per_minute_for_all_profilers" width="640">

Largest input-profiler gap among baselines.

**Throughput**
<img src="../../output/stress_testing/baseline/CTU-Normal-18/plots/throughput_plot" width="640">

**Latency**
<img src="../../output/stress_testing/baseline/CTU-Normal-18/plots/latency_plot" width="640">

Higher spikes; max 52s

Notes:
- The flows/min samples are very small (2-5 points), so throughput trends should be interpreted as coarse, not granular.
- The latency distributions are larger, enabling more confidence in p95/p99 values.

---

## Baseline conclusions (against failure states)
| Check | Result | Rationale |
|---|---|---|
| Soft Break FPS | Not reached in baseline | Mixed captures show <4% throughput gap and near-zero latency. Normal-18 shows a larger gap (23.6%) but without sustained high latency; it is the closest candidate. |
| Hard Break | Not observed | All experiments produced metrics and plots; no indication of process failure in outputs. |

---

## Sudden traffic spikes (scenario 1)

### Scope and artifacts
This scenario covers sudden-spikes experiment. The input traffic pattern is designed to simulate sudden bursts of network activity, with spikes reaching up to 10,281 flows/min every 10 minutes. The goal is to evaluate how Slips handles these abrupt increases in load and whether it can maintain performance without significant degradation or failure.



### Sudden-spikes experiment overview
<div style="width:100%; overflow-x:auto;">

| Experiment name | Input avg (flows/min) | Input peak (flows/min) | Profiler avg (flows/min) | Profiler peak (flows/min) | Avg gap (input vs profiler) | Latency avg (seconds) | Latency p95 | Latency p99 | Summary (plots + metrics) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| sudden_spikes | 439.08 | 10,281 | 439.07 | 10,281 | 0.0006% | 162.96 | 280.0 | 304.0 | Throughput keeps pace with the spike, but latency is very high; soft-break is latency-driven rather than throughput-driven. |

</div>

### Percentile metrics (from metrics.txt)
<div style="width:100%; overflow-x:auto;">

| Metric | p50 | p95 | p99 | Avg |
|---|---:|---:|---:|---:|
| Input flows/min | 253.5 | 944.5 | 5,200.44 | 439.08 |
| Profiler flows/min (all) | 254.0 | 1,222.2 | 5,049.02 | 439.07 |
| Latency (seconds) | 153.0 | 280.0 | 304.0 | 162.96 |

</div>

## Sudden-spikes plots and commentary

### Flows/min captured in this experiment

<img src="../images/immune/c3/sudden_spikes_flows_graph_from_conn_log.png" width="640">

### Flows/min received by Slips profilers


<img src="../images/immune/c3/sudden_spikes_flows_per_minute_for_all_profilers.png" width="640">

Spikes occur every 10 mins up to 10,281 flows/min, this is the stress event.

The conn.log view corroborates a sudden burst pattern rather than sustained elevated traffic.

### Input vs processing speed
<img src="../images/immune/c3/sudden_spikes_throughput_plot.png" >

Profiler throughput mirrors input almost exactly (avg gap ~0.0006%), including at the peak.

**Latency**
<img src="../images/immune/c3/sudden_spikes_latency_plot.png" width="640">

Latency is consistently high (avg 162.96s) with a heavy tail (p95 280s, p99 304s), indicating stress impact despite matched throughput.

## Sudden-spikes conclusions (against failure states)
| Check | Result | Rationale |
|---|---|---|
| Soft Break FPS | Reached (latency-driven) | Throughput keeps up with input, but latency p95/p99 in the 280–304s range indicates significant performance degradation. |
| Hard Break | Not observed | Metrics and plots are complete; no evidence of a process crash. |
