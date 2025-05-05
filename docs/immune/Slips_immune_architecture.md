# Slips Immune Architecture

Slips takes some main concepts from the immunology field to better detect attacks, decide when to block or not and in general to improve its capabilities as intrusion detection system. 

# From Immunology to Cybersecurity

There are many differences of course
- The body can sustain to kill many benign cells in the defense process. Computers not.
- FP can be tolerated a little. In computers not sure.

# Immunology principles

## 1. Creation of new detectors and evoluation

First, new T-cells are created with receptors for antigens. These receptors are randomly created. Each T-cell can detect one antigen.
T-cells do many things, from orchestrating othe immune cells, to killing virus to killing cancer cells.

1. Creates a new t-cell by controlled randomness.
2. Positive selection. T-cells must weakly recognize self-MHC molecules (to ensure they can see peptides in context). This ensures they can do their antigen recognition. If not they are killed.
3. Positive selection. T-cells are verified if they can communicate correctly with the IS.
4. Negative selection. Any receptors that bind self-peptides too strongly are deleted or inactivated.
5. Keep it for later matching.

**Second stage mutation**: After encountering antigen, B cells enter germinal centers and deliberately hypermutate their receptor genes. Those mutations that increase affinity for the antigen are positively selected (they get survival and proliferation signals), while those that reduce binding (or become self-reactive) are lost.

### Cybersecurity interpretation

The negative and positive selection will be done by controlled random creation of detection scripts and using a large dataset of normal.

The idea is to:
1. Create many random detection scripts for Zeek. Random for certain parts, not completely
2. They should be able to recognize some traffic and work and compile.
3. They should be loadable and syntactically correct.
4. They will be run against a DB of benign traffic, if any match happens it is discarded.


## 2. Detection of self
This is a mechanism that is still probably under study, but what we know is all cells in a body have MHC class I molecules that are unique to each body.

### Cybersecurity interpretation

## 3. Easiery to kill
The IS does many things to help killing. One of those is that antibodies clump together around the antigen so it slows down and it is easier to be recognized and kill by other cells.

### Cybersecurity interpretation
It would be possible to DoS the infected computer so it does not send many packets anymore, gets slow and it is easier to contain. Slips will implement this attack technique with ARP poisoning.

Regarding the idea of being easier to identify, this is hard to mimic but one idea could be that Slips asks internally to the operating system and processes to 'shush' for a while and not send packets. If this is possible, then only the traffic of the malicious applications would be visible. This will not be implemented by Slips.


## 4. Communication of parts of the IS
Some part of the Is, like bacteria in the skin and in the gut can communicate with the internal IS to reduce detection, or to increase it. As regulation.

### Cybersecurity interpretation
It would be possible to have public facing IDS and honeypots and to communicate with internal IDS and honeypots for a better defense. This will not be done by Slips.


## 5. Using amount of signals to communicate
The IS uses the amount of signals sent to regulate actions. Like for inflamation. This is an analog signal that regulates activity. Cytokines.


### Cybersecurity interpretation
Local P2P

## 6. How cells die is important for detection

## Once a detection is confirmed parts of the pathogen are taken for context.
Send flows as context

## Communication in the IS
Very complex

Use the local P2P system. It already uses epidemic protocols.

## Multiple activation to avoid FP
Many cells need multiple activations to be ready. Do the same with many detectors.

Also cells do have a timeout to be killed. Add this to detectors.

Layers of activations.

Anergy, killing of T-cells that detect self later on.


## Implement the innate immune system and the adaptive immune system
Do it like this
- The innate is generic in its detections. Fast.
- The adaptive is very strong. Slow. Confirmation is needed.

## Memory cells
Past confirmed detectors that worked.
not sure how to do this.

## Window to the cells
Cells can have windows to see inside.
- If I ask you to show me something, and you show me something bad, I can order you to die.
- If you dont want to show, I will kill you.

Do this with ARP posoning?







# Selection of immune principles for Slips

1. Negative Selection of Detection Mechanisms

2. Decision on detections to avoid False Positives. Regulation. Adaptation. Context

3. Memory

4. Blocking Mechanism

## Decision on detections to avoid False Positives

## Blocking Mechanism

