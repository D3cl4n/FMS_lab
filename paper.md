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
Cryptography and cryptanalysis combine several disciplines. It is necessary to understand mathematics, general computer science, and any relevant cryptographic concepts. Although dated, the FMS attack is no exception. Once a theoretical understanding of the FMS attack is achieved, a practical learning experience is needed to facilitate a deeper understanding. This lab provides a safe learning environment, with the goal of combining theoretical understanding and practical experience. The lab uses Docker containers on an isolated bridge network and a Jupyter Notebook to facilitate the actions. With this lab, students can experiment with the underlying code, without needing to set up the associated infrastructure. Additionally, the Jupyter Notebook introduces the KSA and Pseudorandom Generation Algorithm (PRGA) of RC4, ensuring students have some of the required prerequisite knowledge. 

To my knowledge, there are no open-source, practical labs on the FMS attack. This project bridges that gap. This lab may be adopted as a teaching tool, a self-learning tool, or a playground to experiment with the principles of the attack. Users may find that additional work is required to achieve a complete understanding of the FMS attack, but the lab aims to facilitate learning as much as possible. 

# Functionality of the Lab
The lab comprises four Docker containers, managed with Docker Compose. The client and access point containers communicate bidirectionally, sending ciphertexts and IVs. The attacker container acts as a proxy between the client and access point, intercepting messages and performing the FMS attack. The notebook container launches an instance of Jupyter Notebook, with a notebook for driving the lab actions. The notebook container offers several snippets of code and explanations. First, the notebook explains Python code for a basic implementation of RC4 with a prepended IV. The notebook then uses a pre-captured dataset with entries of the form $[IV_0, IV_1, IV_2, CT_0]$ to demonstrate recovering one byte of $K$. This offline demonstration aims to guide the user on the process for targeting bytes of $K$, while removing any iterative complexity. Finally, the notebook interacts with the other containers, demonstrating a complete FMS attack in the environment. 

To ensure users are not exposing the lab, the containers run on an isolated bridge network `wepnet`. The Jupyter Notebook is accessible from `http://127.0.0.1:8888/`, and is not exposed to the LAN. Additionally, `/var/run/docker.sock` is mounted to the notebook container, allowing it to perform actions with the DockerSDK. 

# Attack Summary
An adversary is able to iteratively recover $K$ through the following steps: [@10.1007/3-540-45537-X_1]

1) For each byte of $K$ the adversary gathers ~60 IVs of the form $[A+3, N-1, X]$. The variable $A$ represents the targeted index of $K$. $N$ is the number of entries in the internal state of RC4, and $X$ is any single byte. 
2) The adversary keeps a probability table $P$ with $N$ members. The value $P_i$ is the score for byte $i$. At the end of the iteration, the index with the maximal score is the most likely candidate for $K_A$. 
3) To recover $K_A$ the adversary iterates over every gathered IV that satisfies the weak form. For each weak IV, the adversary runs the KSA up to $A+3$ iterations. 
4) After the partial KSA execution, the attacker checks the resolved condition $S_1 + S_{S_1} = A + 3$. If this condition is satisfied, and $S_0, S_1$ have not been disturbed by a swap, then the PRGA can be inverted. 
5) For IVs that satisfy the above conditions, the adversary calculates the first keystream byte $KS_0 = 0xAA \oplus CT_0$. $0xAA$ is a partial known plaintext from the SNAP header, used by WEP. 
6) The adversary computes $i = (KS_0 - j - S_{A+3}) \mod 256$ and increments $P_i$. 

# Project Story
This project came about as a way to faciliate understanding on a topic that took me weeks to comprehend. I found myself with a lot of papers and some videos, but no hands-on material to learn the FMS attack. I ended up writing out all the variables by hand, and changing them for each attack iteration to try and understand how $K$ was calculated. While I think that kind of manual work is still necessary, this lab would have made it easier for me. 

# References


