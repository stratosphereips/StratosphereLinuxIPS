# Stress Testing Slips - Baseline Report

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


**Flows/min for all profilers combined**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-1_flows_per_min_for_all_profilers_combined.png" width="640">

Input peaks at 23,404 flows per min.

**Flows/min for each profiler**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-1_flows_per_minute_for_each_profiler.png" width="640">

**Latency over time**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-1_latency_over_time.png" width="640">

Near-zero latency with rare spikes to 32s.

### CTU-Mixed-Capture-2

**Flows/min for all profilers combined**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-2_flows_per_min_for_all_profilers_combined.png" width="640">

**Flows/min for each profiler**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-2_flows_per_minute_for_each_profiler.png" width="640">

**Latency over time**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Mixed-Capture-2_latency_over_time.png" width="640">

### CTU-Normal-18

Largest input-profiler gap among baselines.

**Flows/min for all profilers combined**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Normal-18_flows_per_min_for_all_profilers_combined.png" width="640">

**Flows/min for each profiler**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Normal-18_flows_per_minute_for_each_profiler.png" width="640">

**Latency over time**

<img src="../images/immune/c3/stress_testing/baseline/CTU-Normal-18_latency_over_time.png" width="640">

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

### Flows/min for all profilers combined

<img src="../images/immune/c3/stress_testing/sudden_spikes/sudden_spikes_flows_per_min_for_all_profilers_combined.png" width="640">

### Flows/min for each profiler

<img src="../images/immune/c3/stress_testing/sudden_spikes/sudden_spikes_flows_per_minute_for_each_profiler.png" width="640">

Spikes occur every 10 mins up to 10,281 flows/min, this is the stress event.

### Latency over time

<img src="../images/immune/c3/stress_testing/sudden_spikes/sudden_spikes_latency_over_time.png" width="640">

## Sudden-spikes conclusions
| Check | Result | Rationale |
|---|---|---|
| Soft Break FPS | Reached (latency-driven) | Throughput keeps up with input, but latency p95/p99 in the 280–304s range indicates significant performance degradation. |
| Hard Break | Not observed | Metrics and plots are complete; no evidence of a process crash. |



---
## Soak testing - sustained high traffic (scenario 2)

### Scope and artifacts
This scenario covers soak-testing experiment. The input traffic pattern is designed to simulate sustained high traffic activity. The goal is to evaluate how Slips handles these increases in load for a long period of time and whether it can maintain performance without significant degradation or failure.

### Soak testing experiment overview
<div style="width:100%; overflow-x:auto;">

| Experiment name | Input avg (flows/min) | Input peak (flows/min) | Profiler avg (flows/min) | Profiler peak (flows/min) | Avg gap (input vs profiler) | Latency avg (seconds) | Latency p95 | Latency p99 | Summary (plots + metrics) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| soak_testing | 120.69 | 244 | 120.69 | 244 | ~0% | 60.8 | 61.0 | 61.0 | Throughput keeps pace with the input, latency is stable around 61s. |

</div>

### Percentile metrics (from metrics.txt)
<div style="width:100%; overflow-x:auto;">

| Metric | p50 | p95 | p99 | Avg |
|---|---:|---:|---:|---:|
| Input flows/min | 200.0 | 227.0 | 233.0 | 120.69 |
| Profiler flows/min (all) | 200.0 | 227.0 | 233.0 | 120.69 |
| Latency (seconds) | 61.0 | 61.0 | 61.0 | 60.8 |

</div>

## Soak-testing plots and commentary


### Flows/min for all profilers combined
<img src="../images/immune/c3/stress_testing/soak_testing/soak_testing_6_flows_per_min_for_all_profilers_combined.png" width="640">

### Flows/min for each profiler


<img src="../images/immune/c3/stress_testing/soak_testing/soak_testing_6_flows_per_minute_for_each_profiler.png" width="640">

Sustained traffic around 200 flows/min with a peak of 244 flows/min.

## Latency over time

<img src="../images/immune/c3/stress_testing/soak_testing/soak_testing_6_latency_over_time.png" width="640">

- Hard breaking point identified here: Slips has latency that grows linearly with time, which makes it unusable in the long term (when analyzing live traffic using an interface)




## Soak-testing conclusions
| Check | Result      | Rationale                              |
|---|-------------|----------------------------------------|
| Soft Break FPS | Not Reached | Throughput keeps up with input.   |
| Hard Break | Reached           | Slips has latency that grows linearly. |
