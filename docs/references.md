# References

IEEE style. Swap for your department's if it differs, but keep them consistent
and keep the access dates — a marker checking a dead link is checking whether
you actually read it.

> **Use these properly.** A reference list longer than your citation count is a
> tell. Every entry below should appear in the report body attached to a
> specific claim; delete any you did not use.

---

## Standards and frameworks

[1] National Institute of Standards and Technology, *Guide to Intrusion Detection and Prevention Systems (IDPS)*, NIST SP 800-94, Feb. 2007. [Online]. Available: https://csrc.nist.gov/publications/detail/sp/800-94/final

[2] National Institute of Standards and Technology, *Guide for Conducting Risk Assessments*, NIST SP 800-30 Rev. 1, Sep. 2012. [Online]. Available: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final

[3] National Institute of Standards and Technology, *The NIST Cybersecurity Framework (CSF) 2.0*, NIST CSWP 29, Feb. 2024. [Online]. Available: https://doi.org/10.6028/NIST.CSWP.29

[4] MITRE Corporation, *MITRE ATT&CK® Enterprise Matrix*. [Online]. Available: https://attack.mitre.org/matrices/enterprise/

[5] Center for Internet Security, *CIS Benchmarks*. [Online]. Available: https://www.cisecurity.org/cis-benchmarks

[6] International Organization for Standardization, *ISO/IEC 27005:2022 — Information security, cybersecurity and privacy protection — Guidance on managing information security risks*, 2022.

## Tools and primary documentation

[7] Wazuh Inc., *Wazuh Documentation*, v4.14. [Online]. Available: https://documentation.wazuh.com/

[8] Open Information Security Foundation, *Suricata User Guide*. [Online]. Available: https://docs.suricata.io/

[9] Proofpoint, *Emerging Threats Open Ruleset*. [Online]. Available: https://rules.emergingthreats.net/

[10] G. Lyon, *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*. Sunnyvale, CA, USA: Insecure.Com LLC, 2009.

[11] Wireshark Foundation, *Wireshark User's Guide*. [Online]. Available: https://www.wireshark.org/docs/wsug_html_chunked/

[12] OWASP Foundation, *OWASP Top 10:2021*. [Online]. Available: https://owasp.org/Top10/

[13] European Institute for Computer Antivirus Research, *The Anti-Malware Testfile (EICAR)*. [Online]. Available: https://www.eicar.org/download-anti-malware-testfile/

## Background reading — cite these where you make an argument, not a claim of fact

[14] M. Roesch, "Snort — Lightweight intrusion detection for networks," in *Proc. 13th USENIX Conf. System Administration (LISA '99)*, Seattle, WA, USA, 1999, pp. 229–238.

[15] T. H. Ptacek and T. N. Newsham, "Insertion, evasion, and denial of service: Eluding network intrusion detection," Secure Networks Inc., Tech. Rep., Jan. 1998.

[16] S. Axelsson, "The base-rate fallacy and the difficulty of intrusion detection," *ACM Trans. Inf. Syst. Secur.*, vol. 3, no. 3, pp. 186–205, Aug. 2000.

[17] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in *Proc. IEEE Symp. Security and Privacy*, Oakland, CA, USA, 2010, pp. 305–316.

---

## Which reference belongs where

Markers reward citations that carry weight in an argument. Three that do real
work in this project specifically:

| Use it for | Cite | Why it lands |
|---|---|---|
| §7.4, the evasion results in `07_evasion_test.sh` | **[15] Ptacek & Newsham** | The foundational paper on IDS insertion/evasion. Your slow-scan and fragmentation results are a lab reproduction of a 1998 result — say so, and the section stops being "things that did not work" and becomes replication |
| §7.3, false positives and the baseline you measured | **[16] Axelsson** | The base-rate fallacy explains *why* a detector with excellent accuracy still drowns an analyst in false positives at realistic traffic volumes. This is the theory behind the number `make measure` gives you |
| §1, §2, and the framing of what an IDS is for | **[1] NIST SP 800-94** | The standard reference for IDS/IPS terminology and placement. Cheapest credibility win available |

If you cite [16] against your own measured baseline, you have connected a
measurement you took to a classic result in the literature. That is the single
highest-value paragraph available in this report.
