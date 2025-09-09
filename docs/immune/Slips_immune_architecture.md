# Slips Immune Architecture

The new Slips architecture takes some main ideas from the biology immunology field to better detect attacks, better avoid false positives, better decide when attack and in general to improve its capabilities as intrusion detection system.

This document describes the main aspects of the architecture, how each part of Slips intereacts with each other and why. Other documents will describe the compementary ideas of why Slips uses immunology concepts, the whole set similarities and differences between the human immune system and the artificial proposals, and the broader immunology concepts not implemented in this version of Slips.

## From Immunology to Cybersecurity

The first proposal to see cybersecurity with the lens of immunology already appeared in the 1987 paper "Computer Viruses, Theory and Practice", by calling the malicious software a 'Virus' [1]. In the 1980's and 1990's many papers, software and companies proposed, implemented and describe a 'computer immune system', or 'cybersecurity immune system', even an 'Internet immune system'. These proposals explored different ways to protect computers by trying to learn from the human immune system in their own ways. Even tough there are many papers in the area, most of them only take a very simple and small part of the immnology ideas, or just call their techninque 'immunology' because they do use anomaly detection algorithm. We do not consider any of these proposals as a real, complete and valid transcription and implementation of immunology to the cybersecurity world. To our knowledge, no software system can be run, download or bought in 2025 that really uses immunology concepts.

## Immunology principles used in Slips
The human immune system is an evolved, incredible vast, complex, and not completely known system of millions of parts that interact in million of ways with emergent behaviors to protect humans and help them survive as specie. Our ideas of how we can use it as an analogy for computer security are very simple at best, or completely wrong at worst.

For Slips we choose to implement only some of them as described in the following sections. For each main idea we do a brief biology description and how it was translated into Slips.


# 1. Innate and Adaptive Immune System
The largest and most important separation inside the human immune system (HIS) between the _Innate_ immune system and the _Adaptive_ immune system. So important is the separation that some animals and plants only have an Innate system and not an Adaptive system.


# Detection of non-self and danger signals
The two most accepted theories of how the 
This is a mechanism that is still probably under study, but what we know is all cells in a body have MHC class I molecules that are unique to each body.

## Cybersecurity interpretation




# Adaptive IS and Creation of New Detectors 

First, new T-cells are created with receptors for antigens. These receptors are randomly created. Each T-cell can detect one antigen.
T-cells do many things, from orchestrating othe immune cells, to killing virus to killing cancer cells.

1. Creates a new t-cell by controlled randomness.
2. Positive selection. T-cells must weakly recognize self-MHC molecules (to ensure they can see peptides in context). This ensures they can do their antigen recognition. If not they are killed.
3. Positive selection. T-cells are verified if they can communicate correctly with the IS.
4. Negative selection. Any receptors that bind self-peptides too strongly are deleted or inactivated.
5. Keep it for later matching.

**Second stage mutation**: After encountering antigen, B cells enter germinal centers and deliberately hypermutate their receptor genes. Those mutations that increase affinity for the antigen are positively selected (they get survival and proliferation signals), while those that reduce binding (or become self-reactive) are lost.

## Cybersecurity interpretation

The negative and positive selection will be done by controlled random creation of detection scripts and using a large dataset of normal.

The idea is to:
1. Create many random detection scripts for Zeek. Random for certain parts, not completely
2. They should be able to recognize some traffic and work and compile.
3. They should be loadable and syntactically correct.
4. They will be run against a DB of benign traffic, if any match happens it is discarded.


## Multiple activation to avoid FP
Many cells need multiple activations to be ready. Do the same with many detectors.

Also cells do have a timeout to be killed. Add this to detectors.

Layers of activations.

Anergy, killing of T-cells that detect self later on.


## Memory cells
Past confirmed detectors that worked.
not sure how to do this.


# Attackig the threat
The IS does many things to help killing. One of those is that antibodies clump together around the antigen so it slows down and it is easier to be recognized and kill by other cells.

## Cybersecurity interpretation
It would be possible to DoS the infected computer so it does not send many packets anymore, gets slow and it is easier to contain. Slips will implement this attack technique with ARP poisoning.

Regarding the idea of being easier to identify, this is hard to mimic but one idea could be that Slips asks internally to the operating system and processes to 'shush' for a while and not send packets. If this is possible, then only the traffic of the malicious applications would be visible. This will not be implemented by Slips.




---
# Communication and Signals
The IS uses the amount of signals sent to regulate actions. Like for inflamation. This is an analog signal that regulates activity. Cytokines.


## Cybersecurity interpretation
Local P2P
Use the local P2P system. It already uses epidemic protocols.

## Once a detection is confirmed parts of the pathogen are taken for context.
Send flows as context

