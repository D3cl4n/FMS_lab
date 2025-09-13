---
title: A Didactic Lab of the FMS Attack on WEP and RC4
tags:
    - Cryptography
    - Cryptanalysis
    - Stream Ciphers
    - RC4
    - FMS Attack
    - Python
    - Jupyter Notebook

authors:
    - name: Declan P. Murphy
      orcid: 0009-0008-1853-4453

date: 12 September 2025
bibliography: paper.bib
---

# Introduction
This paper presents a didactic lab of the FMS attack on RC4 with a prepended IV. The FMS attack, named after researchers Scott Fluhrer, Itsik Mantin, and Adi Shamir, exploits a statistical bias of the RC4 Key Scheduling Algorithm (KSA). This statistical bias, and other weaknesses of RC4, have rendered the cipher broken. Notably, the FMS attack broke the Wireless Equivalent Privacy (WEP) protocol, allowing an adversary to iteratively recover bytes of the root key [@asiacrypt-2005-378]. 

# Statement of Need
Cryptography and cryptanalysis combine serveral disciplines. It is necessary to understand mathematics, general computer science, and any relevant cryptographic concepts. Although dated, the FMS attack is no exception. Once a theoretical understanding of the FMS attack is achieved, a practical learning experience is needed to facilitate a deeper understanding. This lab provides a safe learning enviornment, with the goal of combining theoretical understanding and practical experience. The lab uses docker containers on an isolated bridge network and a Jupyter Notebook to facilitate the actions. With this lab, students can experiment with the underlying code, without needing to setup associated infrastructure. Additionally, the Jupyter Notebook introduces the KSA and Pseudorandom Generation Algorithm (PRGA) of RC4, ensuring students have some of the required prerequisite knowledge. 

# References


