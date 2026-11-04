# TCP2SHELL IMPACT ANALYSIS

CVE-2026-98432 | Remote use-after-free in the Linux kernel's IPv4 TCP handshake | CVSS 3.1: 9.8 (kernel.org, CNA, and Red Hat) | SUSE, Amazon and Oracle: 8.1 Important | Ubuntu priority: critical

Data cut-off: 4 November 2026, 14:00 UTC (version 1.1). Version 1.0 had a cut-off of 30 October 2026, 06:30 UTC. Things are still moving, so check NVD, CISA KEV, EPSS and your distro or vendor advisory again before you act on anything here.

**What changed since version 1.0:**

- Red Hat shipped fixed kernels for RHEL 8, 9 and 10 on 1 November and now rates the bug Critical, 9.8. Rocky Linux, AlmaLinux and Oracle Linux's Red Hat compatible kernel followed. Amazon Linux 2, EKS and Bottlerocket are fixed too.
- Ubuntu raised its priority to critical, but its fixes were still in testing on 4 November.
- Red Hat, AlmaLinux and AWS published packet-filter rules that drop IPv4 TCP packets carrying IP options. Red Hat says turning MPTCP off is not a complete mitigation.
- Live patches now exist from SUSE and TuxCare, besides Oracle Ksplice.
- Still no exploitation in the wild and still not in CISA KEV. The reporters' exploit code was still unpublished on 3 November. EPSS rose to 0.0076.
- A maintainer posted the fix for the IPv6 sibling issue on 3 November, and it was still under review on 4 November.
- National CERTs in the Netherlands, Canada, France and Hong Kong now name the CVE.

---

## EXECUTIVE SUMMARY

### The situation at a glance

- **What:** A use-after-free in the Linux kernel's IPv4 TCP handshake, tracked as CVE-2026-98432. When a TCP SYN carries IPv4 options (Record Route or Timestamp), the kernel keeps those options for the connection and can free them while another CPU is still using them. The result can be leaked kernel memory, memory corruption, a kernel panic or, according to the write-up published by the team that reported the bug, commands run as root. The bug has no public nickname. TCP2Shell is this analysis's own label for it, and every advisory uses the CVE number. It was reported by Xinyang Ge. The fix and the CVE share one title: "ipv4: free inet_opt and ireq_opt after an RCU grace period".
- **Risk level:** CRITICAL for internet-facing Linux servers that accept inbound IPv4 TCP connections directly, above all those with multipath TCP (MPTCP) listeners. HIGH everywhere else. kernel.org, the CVE Numbering Authority (CNA), scores it 9.8 Critical (CVSS 3.1), and Red Hat now agrees. SUSE, Amazon Linux and Oracle Linux still rate it Important at 8.1. Ubuntu raised its priority to critical on 3 November, and Debian has set no urgency.
- **Impact:** Kernel heap memory can leak into the SYN-ACK that goes back to the attacker. Out-of-bounds kernel writes with potential control-flow corruption are possible, and so is a kernel panic or an oops. That is the CNA's scoring narrative. No login and no user interaction are needed, only an IPv4 route to a listening TCP socket. The reporters' write-up says a remote attacker can run arbitrary commands as root on a server with an MPTCP listener. The bug is server side only: outgoing client connections do not use the vulnerable path.
- **Status:** Fixed upstream in Linux 7.3, 7.2.10, 6.18.56, 6.12.113, 6.6.159, 6.1.190, 5.15.223 and 5.10.272. The 7.2 line reached end of life with 7.2.15 on 1 November. There is no upstream fix for 5.4 and older or for end-of-life non-LTS lines such as 7.1, 7.0 and 6.19, so those depend on a vendor backport. The fix and its explanation were public on the netdev mailing list from 29 September 2026, 16 days before the CVE was published. Red Hat shipped fixed kernels for RHEL 8, 9 and 10 on 1 November, and Rocky Linux, AlmaLinux and Oracle Linux's Red Hat compatible kernel followed. Debian, Oracle Linux (UEK), SUSE, Amazon Linux 2 and 2023, and Azure Linux 3.0 ship fixed kernels too. Ubuntu had released no fix on 4 November: its generic kernels were in testing (the -proposed pocket), and its cloud kernel flavours were still pending. No exploitation in the wild has been reported, the reporters' exploit code was still unpublished on 3 November, and the CVE is not in CISA's Known Exploited Vulnerabilities catalog (KEV).
- **Who's safe:** Hosts that run a fixed kernel and have rebooted into it. Installing the package is not enough, because the running kernel stays vulnerable until the reboot. Kernels older than 4.4 are not affected, and Red Hat says RHEL 6 and 7 do not contain the vulnerable code. Hosts with no listening TCP port that untrusted IPv4 networks can reach are less exposed, and so are IPv6-only services.
- **Who's at risk:** Any Linux server on a kernel from 4.4 up to the fixed versions that has a listening TCP socket an outsider can reach over IPv4. The path the reporters demonstrated needs an MPTCP listener. Upstream kernels enable MPTCP by default, and programs whose main module declares go 1.24 or later open MPTCP listeners by default (Caddy, Traefik and Kubernetes are among the 18 Go servers checked, see Software that opens MPTCP listeners). Containers and Kubernetes nodes are in scope because they share the host kernel. Hosts on releases without a released fix are worst off: every Ubuntu release (22.04 and later in testing, 20.04, 18.04 and 16.04 marked "needed"), Debian stretch and buster (end of life), OpenShift 4 (RHCOS still listed as affected) and CentOS Stream 9 and 10.

*Sources: kernel.org CVE record (CNA), ChangeLog files and releases page, NVD, CISA KEV feed, the netdev mailing list, the reporters' write-up, Go security team announcement, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle Linux, Rocky Linux and AlmaLinux security pages, Red Hat bulletin RHSB-2026-016, Canonical blog (2 November 2026), AWS bulletin 2026-160-AWS, Microsoft update guide (Azure Linux), Go 1.24 release notes*

### What this means for your organization

The bug sits in the kernel's TCP code, so updating an application, a library or a container image doesn't fix it. The fix is a vendor kernel and a reboot. Containers share the host kernel, so you patch the node, not the pod.

A host is exposed when it runs a kernel from 4.4 up to the fixed versions and has a listening TCP socket that an attacker can reach over IPv4 with the attacker's IP options intact. Four routes lead there:

- MPTCP listeners. This is the path the reporters demonstrated. Upstream kernels default `net.mptcp.enabled` to 1, the setting applies per network namespace, and every new namespace starts at 1. Go programs whose module declares go 1.24 or later open MPTCP listeners by default.
- Plain TCP listeners. The Go security team says the underlying bug is not specific to MPTCP and that systems with no MPTCP listener may be vulnerable to similar attacks. Nobody has publicly shown code execution without an MPTCP listener.
- Dual-stack listeners. An IPv6 socket bound to `::` without `IPV6_V6ONLY` also takes IPv4 connections, and the kernel handles those with the IPv4 code. Native IPv6 connections don't take the first path, because the IPv6 code duplicates the options.
- Request migration. Setting `net.ipv4.tcp_migrate_req=1`, or loading a `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` program, opens a second path to the same bug, because the cloned and old request sockets share the same options.

Some services are reached from the internet only through a proxy that terminates TCP, such as the Cloudflare proxy, AWS ALB, CloudFront or any reverse proxy. The attacker's IPv4 options don't reach the origin kernel in that setup. For its own services, AWS's bulletin says customers behind ALB, CloudFront, API Gateway or an NLB TLS listener "do not receive TCP connections from untrusted sources directly when following best practices", and that Global Accelerator drops every IPv4 packet that carries IP options. The reasoning holds only if the origin isn't reachable directly, so lock the origin firewall to the proxy's IP ranges. The proxy's own kernel is the proxy operator's problem. Services published only through outbound tunnels (for example Cloudflare Tunnel) have no internet-facing listener. Layer 4 passthrough load balancers (AWS NLB with TCP listeners, Google Cloud passthrough network load balancers) forward packets, and no documentation says they strip IP options, so treat services behind them as exposed. The same goes for cloud networks: no AWS, Google Cloud or Azure documentation says their virtual networks drop or strip IPv4 options, and security groups and network ACLs can't match IP options. Treat the cloud network as unknown, not as a filter.

One reading you'll see needs a footnote: that only MPTCP hosts are at risk. The reporters' write-up names an MPTCP listener as the target. It doesn't explain why MPTCP is needed and names no tested kernel versions or distributions. The Go security team agrees the demonstrated exploit requires an MPTCP listener, but says the bug itself is not MPTCP specific. Red Hat's bulletin RHSB-2026-016 (last updated 4 November) goes further: having MPTCP enabled is not a precondition, and turning it off "is not a complete mitigation". Turning MPTCP off closes the demonstrated path and nothing more, so it is a stopgap and not a fix.

If an attacker gets this working against one of your servers, they can:

- Read kernel memory. Stale options are copied into the SYN-ACK that goes back to the peer, which can disclose kernel heap memory. The reporters' write-up uses such a leak to defeat kernel address randomization (KASLR) remotely.
- Write out of bounds in the kernel, with potential control-flow corruption.
- Crash the machine with a kernel panic (`skb_under_panic`) or an oops.
- Run arbitrary commands as root, according to the reporters' write-up, on a server with an MPTCP listener.
- Use whatever the host can reach, such as the databases and internal services it talks to, and the secrets stored on it.

The quiet part is the retry. A lost race only fails the handshake, so an attacker can retry indefinitely, and a successful exploit is designed not to crash. Clean kernel logs prove nothing.

Real-world context: The fix was public on the netdev mailing list from 29 September 2026, and the commit message of its first version explains the use-after-free. That is 16 days before the CVE was published and 28 days before the reporters' write-up. The reporters' write-up (27 October 2026, updated 28 October 2026) describes remote command execution as root against servers with an MPTCP listener. Its proof of concept took 48 minutes to leak a kernel pointer and another 5 minutes to reach command execution. On 3 November The Hacker News reported that the reporters' exploit code was still unpublished. No exploitation in the wild has been reported. Rapid7 lists `exploited_in_wild` as false, Wiz and Feedly show no evidence, Previdian says "No Exploitation Yet", AWS has "no evidence" of use, Fortinet lists it as not known exploited, and the CVE is not in CISA KEV. The EPSS score rose from 0.00388 on 29 October to 0.0076 (55.3rd percentile) on 3 November. Red Hat moved its own score to the CNA's 9.8 by 4 November, while SUSE, Amazon Linux and Oracle Linux stay at 8.1 (see Severity metrics).

A GitHub search on 4 November found 71 repositories that mention the CVE, up from 11 on 30 October. Their descriptions include checkers, mitigations, a trigger that says it does no code execution, and a "lab root-shell kit" that says it is not a stock remote exploit. None is verified. Running unknown proof-of-concept code is a common way to get compromised, so leave them alone. National CERTs in the Netherlands (NCSC-2026-0461), Canada (AV26-1108) and France (CERTFR-2026-AVI-1432) issued advisories on 30 October, and HKCERT followed on 3 November.

*Sources: kernel source (net/ipv4 and net/ipv6), kernel.org CVE record (CNA), kernel documentation (MPTCP and IP sysctls), the reporters' write-up, Go security team announcement, Go issue 82717, Rapid7, Wiz, Feedly, Previdian, Fortinet PSIRT, AWS bulletin 2026-160-AWS, CISA KEV feed, FIRST EPSS API, Red Hat, Amazon Linux and Oracle Linux CVE pages, GitHub repository search, NCSC-NL, CCCS, CERT-FR and HKCERT advisories, AWS, Google Cloud, Azure and Cloudflare documentation*

### Immediate actions required

HOUR 1: Find every exposed Linux host

1. List the servers, cloud instances, Kubernetes nodes and appliances that run Linux. Containers share the host kernel, so list the nodes, not the pods. Include the machine images you build yourself, so new instances don't start on an old kernel.
2. Get the running kernel with `uname -r` on each host. The running kernel is the one that counts: it stays vulnerable until the host reboots, whatever is installed on disk. Vendor kernels carry their own version numbers, so judge them against the fixed package in Where the fix comes from, not against the upstream numbers in Affected versions: quick lookup.
3. Mark the hosts with a listening TCP socket that untrusted IPv4 networks can reach, internet-facing ones first. `ss -Mlnp` (as root) lists MPTCP listeners and `ss -tlnp` lists all TCP listeners. Mark Go services too, because Go programs whose module declares go 1.24 or later open MPTCP listeners by default. A host reachable only through a proxy that terminates TCP is lower priority, but only if its firewall admits just the proxy's IP ranges.

DAY 1: Patch and reboot

1. Install the vendor kernel that has the fix (see Where the fix comes from). Patch internet-facing hosts with MPTCP listeners or Go services first, then every other host that accepts inbound IPv4 TCP.
2. If you suspect a host, capture memory and volatile state before you reboot it. A kernel exploit can leave no file on disk, and a reboot destroys memory evidence.
3. Reboot every patched host. This is not optional unless you use a live patch: Oracle Ksplice, SUSE live patching (SLE 12 SP5 and 15 SP4 to SP7) and TuxCare KernelCare (Debian 13 at least) have them. None was found for Ubuntu Livepatch, RHEL kpatch or Amazon Linux. After the reboot, run `uname -r` again and confirm the fixed kernel is the one running.
4. If a reboot has to wait, drop inbound IPv4 TCP packets that carry IP options at the host firewall or the network edge, and turn MPTCP off by setting `net.mptcp.enabled` to 0 and then restarting the services that listen. Both are partial. Red Hat, AlmaLinux and AWS now publish packet-filter rules, and Red Hat prefers the filter to turning MPTCP off. Red Hat also says the filter reduces exposure but "cannot fully prevent" exploitation. Red Hat and a CIQ kernel engineer both note that it misses traffic between pods or containers on the same host. Turning MPTCP off leaves plain TCP exposed. The commands, limits and rollback are under IMMEDIATE ACTIONS in the PROTECTION ROADMAP.

DAY 2: Look for compromise

1. Search the kernel log for `skb_under_panic` and for oopses that name `ip_options_build` or `ip_build_and_send_pkt`. An oops that names either function is a strong sign of attempts. KASAN reports ("BUG: KASAN: ...") appear only on kernels built with `CONFIG_KASAN`. Clean logs prove nothing, because a lost race leaves no crash.
2. Look for user-space processes whose parent is a kernel thread, usually kthreadd (PID 2). The reporters' write-up says the payload ends by running a shell command as root from kernel context. Legitimate helpers (modprobe, coredump and hotplug helpers) show up too, so baseline first.
3. Look in network records for many handshakes from one source over tens of minutes, with Record Route or Timestamp options and retransmitted SYNs. That is the pattern in the reporters' proof of concept, which took 48 minutes to leak a kernel pointer.
4. If anything looks off, treat the host as fully compromised and rotate every secret it holds or can reach.

### Business impact assessment

Financial risk:

- No confirmed compromise has been reported, so there is no incident cost to quote for this bug.
- The fix itself is a vendor kernel update and a reboot. The costly cases are hosts on releases that have no released fix yet: every Ubuntu release (22.04 and later in testing, 20.04, 18.04 and 16.04 marked "needed") and Debian stretch and buster (end of life). Debian bullseye is fixed only through Freexian ELTS.
- Finding every host is the hidden cost. A machine image or a managed node pool can carry an old kernel into every new instance.

Operational risk:

- Every fix needs a reboot, so every service on the host restarts. Plan the windows.
- Managed platforms may lag. On 30 October the latest AKS node image (202610.16.1) and Bottlerocket OS (v1.68.0) still carried kernels from before the fix. Bottlerocket v1.68.1 (2 November) has the fix, and AKS rolled out node image 202610.23.0, whose kernel wasn't confirmed.
- The stopgaps have costs. Hosts that use CIPSO labels (NetLabel, multi-level security) carry IP options on purpose, so the packet drop can break them: test before you enforce. RFC 7126 recommends dropping Record Route and Timestamp options by default, so legitimate internet traffic with them is rare. The rules aren't persistent. On a host that forwards traffic to containers the same hook sees that traffic too, and CNI plugins with eBPF datapaths can steer packets past the host's netfilter hooks.
- Turning MPTCP off only affects sockets created afterwards, so existing listeners keep accepting MPTCP until their service restarts. Every new container network namespace starts with MPTCP on again.
- Red Hat now publishes a packet-filter mitigation, and says it reduces exposure but can't fully prevent exploitation. The Go security team calls disabling MPTCP program by program "a fragile mitigation", and Canonical calls updates "the only appropriate mitigation". The best fix is a patched kernel.
- Cloudflare WAF rules do nothing here, because they work on HTTP and can't see IP options. Magic Transit customers can match packets with options at Cloudflare's edge with the Network Firewall (Magic Firewall) fields `ip.hdr_len` and `ip.opt.type`. Cloud security groups and network ACLs can't.

Legal risk:

- If a compromised service holds personal data, breach notification clocks start when you become aware of the breach. The deadlines by jurisdiction are in COMPLIANCE & LEGAL REQUIREMENTS.

*Sources: Red Hat, Ubuntu, Debian, Amazon Linux, SUSE and Oracle Linux security pages, Red Hat bulletin RHSB-2026-016, Canonical blog (2 November 2026), Debian ELTS (Freexian) tracker, AKS and Bottlerocket release notes, Go security team announcement, RFC 7126, kernel.org documentation, Cloudflare Network Firewall documentation*

---

## RISK DASHBOARD

### Severity metrics

| Metric | Rating | What it means |
| --- | --- | --- |
| **Overall risk** | CRITICAL for exposed internet-facing hosts, HIGH elsewhere | kernel.org (the CNA) and Red Hat score it 9.8 Critical (CVSS 3.1). SUSE, Amazon Linux and Oracle Linux score it 8.1 and call it Important. Ubuntu's priority is critical. Other sources are in the table below |
| **Attack complexity** | LOW per the CNA and Red Hat, HIGH per SUSE, Amazon and Oracle | The CNA vector is AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H: network, low complexity. Red Hat moved from AC:H to AC:L. The split is explained under the second table. The reporters' proof of concept took 48 minutes to leak a kernel pointer and another 5 minutes to reach command execution |
| **Authentication needed** | NONE | PR:N. An unauthenticated remote peer that can reach a listening TCP socket over IPv4 is enough |
| **User interaction** | NONE | UI:N. Nobody has to click anything |
| **Reach** | SERVER SIDE ONLY | The code runs for incoming connections to listening sockets. Outgoing client connections don't use it. Native IPv6 connections avoid the first path, but IPv4 connections that arrive at a dual-stack IPv6 socket don't |
| **Patch available** | YES for every maintained upstream line | Fixed releases came out from 11 October 2026 (7.2.10 and 6.18.56), the other LTS lines followed on 15 October 2026, and 7.3 shipped on 18 October 2026. Nothing upstream for 5.4 and older or for end-of-life non-LTS lines, and 7.2 reached end of life with 7.2.15 on 1 November. Vendors differ (see Where the fix comes from) |
| **Active exploitation** | NOT REPORTED IN THE WILD | The reporters' write-up describes root command execution against servers with an MPTCP listener, and the reporters' exploit code was still unpublished on 3 November. Rapid7, Previdian, AWS and Fortinet report no exploitation. The 71 GitHub repositories that mention the CVE are unverified. Not in CISA KEV (catalog 2026.11.03) |
| **EPSS** | 0.0076 (55.3rd percentile) | Reading of 3 November 2026, up from 0.00388 on 29 October |
| **NVD record** | RECEIVED, NO NVD SCORE | NVD received the record on 15 October 2026 at 13:17 UTC and last changed it on 3 November. The page shows the CNA's 9.8 and no NVD score |

Ratings by source:

| Source | Rating | Note |
| --- | --- | --- |
| kernel.org (CNA) | CVSS 3.1 9.8 Critical | Vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Added to the CVE record on 24 October 2026 |
| NVD | Status "Received" | No NVD score. The page shows the CNA's 9.8 |
| Red Hat | Critical, CVSS 3.1 9.8 | AV:N/AC:L on 4 November. It was Important 8.1 (AC:H, draft) on 30 October. CWE-825 |
| SUSE | important, CVSS 3.1 8.1, CVSS 4.0 9.2 | Unchanged on 4 November. The only CVSS 4.0 score in this table |
| Amazon Linux | Important, CVSS 8.1 | ALAS2023-2026-3251, -3335 and -3365, ALAS2-2026-4065 |
| Oracle Linux | Important, CVSS 8.1 | Preliminary. UEK and Red Hat compatible kernel errata (see Where the fix comes from) |
| Ubuntu | Priority critical | Raised from High on 3 November. No Ubuntu Security Notice yet |
| Debian | Urgency not yet assigned | Fixed kernels are out (see Where the fix comes from) |
| GitHub advisory GHSA-qp6h-4hvh-qqqc | Critical 9.8 | Unreviewed |
| EPSS | 0.0076 (55.3rd percentile) | 3 November 2026, up from 0.00388 on 29 October |
| CISA KEV | Not listed | Catalog 2026.11.03 |

The 9.8 versus 8.1 split comes down to attack complexity. kernel.org says both racing sides are attacker-induced, so it scores AC:L, and Red Hat now agrees. SUSE, Amazon Linux and Oracle Linux still score the race as hard, AC:H. The reporters' write-up says a lost race only fails the handshake and does not crash the system, so an attacker can keep retrying.

You may see 5.9 quoted. BleepingComputer (30 October) gave it as Red Hat's score, and The Hacker News (3 November) says it was Red Hat's first rating, Moderate, before Red Hat raised it. Red Hat's page showed 8.1 on 30 October and shows 9.8 now. Don't use 5.9 as a current score.

My read: treat it as critical for internet-facing Linux servers that accept inbound IPv4 TCP connections directly, above all those with MPTCP listeners, and as high everywhere else. The reporters describe root command execution against an MPTCP listener, the CNA and now Red Hat score it 9.8, and the fix has been public since 29 September 2026. Against that, the reporters' exploit code was still unpublished on 3 November, nobody has reported exploitation, SUSE, Amazon and Oracle still call the race hard, and nobody has publicly shown code execution without an MPTCP listener. Hosts that only an internal network can reach stay at high, because anyone already inside that network is a possible attacker.

*Sources: kernel.org CVE record (CNA), NVD, Red Hat, SUSE, Amazon Linux, Oracle Linux, Ubuntu and Debian CVE pages, GitHub advisory database, FIRST EPSS API, CISA KEV feed, Rapid7, Previdian, AWS bulletin 2026-160-AWS, Fortinet PSIRT, GitHub repository search, the reporters' write-up, Wiz, Feedly, BleepingComputer (30 October 2026), The Hacker News (29 October and 3 November 2026)*

### Affected versions: quick lookup

| Kernel line | Status on 4 November 2026 | Affected releases | Fixed in | Released | Latest on kernel.org |
| --- | --- | --- | --- | --- | --- |
| 7.3 | Stable (7.4-rc1 is mainline since 1 November) | Before 7.3-rc7 | 7.3-rc7, then 7.3 | 12 October 2026 (rc7), 18 October 2026 (7.3) | 7.3.1 |
| 7.2 | End of life since 7.2.15 (1 November 2026) | 7.2 to 7.2.9 | 7.2.10 | 11 October 2026 | 7.2.15, the last |
| 6.18 | LTS | 6.18 to 6.18.55 | 6.18.56 | 11 October 2026 | 6.18.60 |
| 6.12 | LTS | 6.12 to 6.12.112 | 6.12.113 | 15 October 2026 | 6.12.115 |
| 6.6 | LTS | 6.6 to 6.6.158 | 6.6.159 | 15 October 2026 | 6.6.161 |
| 6.1 | LTS | 6.1 to 6.1.189 | 6.1.190 | 15 October 2026 | 6.1.191 |
| 5.15 | LTS, end of life projected for December 2026 | 5.15 to 5.15.222 | 5.15.223 | 15 October 2026 | 5.15.224 |
| 5.10 | LTS, end of life projected for December 2026 | 5.10 to 5.10.271 | 5.10.272 | 15 October 2026 | 5.10.273 |
| 5.4 and older, back to 4.4 | Not among the lines kernel.org maintains | All | None upstream, depends on the vendor backport | n/a | n/a |
| End-of-life non-LTS lines (for example 7.1, 7.0, 6.19) | End of life | All | None upstream, depends on the vendor backport | n/a | n/a |
| Before 4.4 | Not affected | None | n/a | n/a | n/a |

Two things to know about this table. First, the ranges follow from the commit that introduced the bug and the first fixed release of each line. They were not tested release by release. Second, distribution kernels don't follow these numbers: vendors backport the fix under their own version strings, so a distro kernel that looks old can contain the fix and one that looks new can lack it. Ubuntu 26.04 resolute, for example, runs a 7.0 kernel. Upstream has no fix for the 7.0 line, and Ubuntu's own fix (7.0.0-43.43) is prepared but not released.

The bug entered with commit 079096f103fa ("tcp/dccp: install syn_recv requests into ehash table"), authored on 2 October 2015 and first released in Linux 4.4 in January 2016. Kernels before 4.4 are not affected. The request migration path comes from commit c905dee62232 ("tcp: Migrate TCP_NEW_SYN_RECV requests at retransmitting SYN+ACKs."), authored on 12 June 2021 and first released in Linux 5.14. The mainline fix is commit e3f33b0a1d89, committed on 5 October 2026. It makes two one-line changes, a `kfree_rcu()` call in `inet_sock_destruct()` and another in `tcp_v4_reqsk_destructor()`. It carried no "Cc: stable" tag, yet every maintained line got it.

One related gap is still open. The CVE text says `tcp_v6_reqsk_destructor()` has the same migration problem with `ipv6_opt`, which only CALIPSO sets, and that a separate patch will fix it. A third party proposed a fix on the netdev list on 19 October 2026. On 3 November the networking maintainer Eric Dumazet posted his own, "tcp: ipv6: free ireq->ipv6_opt after an RCU grace period", which had three Reviewed-by tags but wasn't applied by 4 November, 14:00 UTC. He calls the issue untriggered and only plausible. Three more patches on related IPv6 lifetimes were under review at the same time, and an automated review on 4 November said `ireq->pktopts` is still freed without RCU on migration. None of this has a CVE yet.

Quick status check:

```bash
# running kernel version, compare with the fixed versions
uname -r
# installed kernel package version
dpkg -s linux-image-$(uname -r) | grep '^Version'     # Debian and Ubuntu
rpm -qa 'kernel*' | sort                            # RHEL family, Fedora, Amazon Linux (kernel6.12, kernel6.18), Oracle (kernel-uek), SUSE (kernel-default)
# MPTCP and migration settings
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req
# MPTCP listening sockets in the current network namespace, with processes (run as root)
ss -Mlnp
```

- On an upstream kernel, if `uname -r` prints a release before the fixed one for its line, the host is vulnerable. A host that installed a fixed kernel but didn't reboot still prints the old one, and that is the one that counts.
- On a vendor kernel, compare the package version with the fixed package in Where the fix comes from.
- A value of 1 for `net.mptcp.enabled` means MPTCP sockets can be created, which is the upstream default. A value of 1 for `net.ipv4.tcp_migrate_req` turns on request migration, and the default is 0.
- Anything `ss -Mlnp` lists is an MPTCP listener, the path the reporters demonstrated.
- Containers have no kernel of their own, so run `uname -r` on the node. The MPTCP setting is per network namespace and every new one starts at 1, so a host setting doesn't carry into containers. Run the socket check inside each container's namespace too. The full assessment steps are in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: kernel.org ChangeLog files and releases page (rechecked on 4 November 2026), kernel.org CVE record (CNA), kernel source commit history, kernel documentation (MPTCP and IP sysctls), the netdev mailing list and its marc.info archive (19 October and 3 to 4 November 2026), Ubuntu CVE tracker*

### Where the fix comes from

Two rules decide whether you are fixed. First, a fix only counts once the host has rebooted into it. Second, every vendor ships its own build under its own version numbers, so the table gives each vendor's fixed package. "Inferred" means we compared the vendor's kernel version with the upstream fixed versions, and no vendor notice names the CVE. "Pending" means the vendor has no released fix yet.

| Platform | Status on 4 November 2026 | Fixed package or version | Notes |
| --- | --- | --- | --- |
| Debian | Fixed for bookworm, trixie, forky and sid (unchanged since 30 October) | bookworm `linux` 6.1.190-1 (DLA-4841-1, 17 October 2026), bookworm `linux-6.12` 6.12.113-1~deb12u1 (DLA-4850-1, 22 October 2026), trixie 6.12.113-1 (DSA-6568-1, 16 October 2026), forky 7.2.12-1, sid 7.2.13-1 | bullseye is fixed only through Freexian ELTS: 5.10.272-1 (ELA-1846-1) and `linux-6.1` 6.1.190-1~deb11u1 (ELA-1850-1). stretch and buster are end of life. Freexian's tracker also lists its `linux-6.1` package as fixed for them, which wasn't checked further. Debian has set no urgency |
| Ubuntu | Pending: fixes in testing (the -proposed pocket), no Ubuntu Security Notice | None released | Priority critical since 3 November. Canonical said on 2 November that fixes are in -proposed for testing and that updates are "the only appropriate mitigation". Prepared versions: 22.04 jammy 5.15.0-203.213, 24.04 noble 6.8.0-149.149, 26.04 resolute 7.0.0-43.43, 26.10 7.3.0-10.10. The aws, azure, gcp, gke and oracle kernel flavours on jammy and noble are still pending. 20.04, 18.04 and 16.04 are "needed" (affected, no fix yet). 14.04 is not affected. No Livepatch fix is listed |
| Red Hat | Fixed on 1 November (Critical, 9.8) | RHEL 8.10 kernel 4.18.0-553.182.1.el8_10 (RHSA-2026:93414), RHEL 9 5.14.0-687.64.1.el9_8 (RHSA-2026:93412), RHEL 10 6.12.0-211.72.1.el10_2 (RHSA-2026:93413) | Errata for the EUS, E4S, AUS, TUS and SAP streams followed through 4 November. OpenShift 4 (RHCOS 8 and 9) is still listed as affected. RHEL 6 and 7 are not affected (vulnerable code not present). Bulletin RHSB-2026-016 gives an nftables mitigation. Bugzilla 2553390 is still NEW, and no kpatch exists |
| AlmaLinux, Rocky Linux | Fixed | Rocky Linux 8, 9 and 10: RLSA-2026:93414, 93412 and 93413 (3 November). AlmaLinux 8: ALSA-2026:93414 and 93415. AlmaLinux 9 and 10: fixed kernels in the repositories since 2 November, with the CVE in the changelog | No AlmaLinux advisory ID was found for 9 and 10. AlmaLinux's blog post of 30 October (updated 2 November) also gives interim mitigations |
| Oracle Linux | UEK and the Red Hat compatible kernel fixed (Important) | UEK: ELSA-2026-500397, -500398 and -500399 (16 October), then ELSA-2026-500573 (R6 5.4.17-2136.361.4), -500574 (R7 5.15.0-326.222.4) and -500572 (R8 6.12.0-208.112.5) on 2 November. RHCK: ELSA-2026-93414 (OL8), -93412 (OL9) and -93413 (OL10), 2 November | Ksplice updates for UEK R6, R7 and R8 on 19 October 2026 |
| SUSE | Fixed for most products (important) | kernel-default at least 6.12.0-160000.40.1 for SLE 16.0 and SLE Micro 6.2; 6.4.0-150700.53.90.1 for SLES 15 SP7; 6.4.0-150600.23.143.1 for SLES 15 SP6 LTSS; 5.14.21-150500.55.195.1 for SLES 15 SP5 LTSS and Micro 5.5; 5.14.21-150400.24.246.1 for SLES 15 SP4 LTSS and Micro 5.3 and 5.4 | SLE Micro 6.0 and 6.1 are released too, and SLES 12 SP5 is in progress. Live patches are listed for SLE 12 SP5 and 15 SP4 to SP7 (for example SUSE-SU-2026:5059-1, 3 November). SLES 15 SP1 to SP3 LTSS are still affected. SLE 11 SP4 is not affected |
| Amazon Linux | Fixed for AL2023 and AL2 (Important, CVSS 8.1) | AL2023: kernel6.12 6.12.113-138.209.amzn2023 (ALAS2023-2026-3335), kernel6.18 6.18.56-125.164.amzn2023 (ALAS2023-2026-3251) and the package named "kernel" 6.1.189-236.400 (ALAS2023-2026-3365). AL2: kernel 4.14.355-287.758 (ALAS2-2026-4065) and the 5.4, 5.10 and 5.15 extras (ALAS2KERNEL-5.4-2026-135, ALAS2KERNEL-5.10-2026-137, ALAS2KERNEL-5.15-2026-120) | The newer advisories are dated 30 October. AWS bulletin 2026-160-AWS (31 October) says to update and reboot. No live patch for this CVE |
| Azure Linux 3.0 | Fixed | kernel 6.6.159.1-1.azl3 (Microsoft vendor fix, production repository since 20 October 2026) | Azure Linux 4.0 is under investigation. Microsoft's update guide lists the CVE for Azure Linux with customer action required |
| Alpine | At or above the fix (inferred) | linux-lts 6.12.114 (3.21 and 3.22), 6.18.59 (3.23, 3.24 and edge) | The Alpine tracker still has no package data |
| Fedora and Arch | Fixed (inferred) | Fedora 44 kernel 7.2.15, Arch linux 7.2.14 and linux-lts 6.18.60 | Inferred from the kernel version, as defined above |
| GKE Container-Optimized OS | Mixed | The release notes for m121, m125, m129 and m133 name the fix (m133 in cos-133-19999-44-174, 30 October). Below the fix (inferred) on 30 October: m113 (6.1.161), m117 (6.6.157) | GKE's release notes still listed 44-159 for 1.37 on 4 November. No GKE bulletin names the CVE |
| EKS | Fixed in the AL2023 AMIs | AL2023 AMI v20261031, named in AWS bulletin 2026-160-AWS, after v20261026 (27 October) had fixed the 6.12 and 6.18 kernels. The ECS-optimized AMI 20261031 is fixed too | The 6.1 variant was not fixed in v20261026 |
| Bottlerocket | Fixed | v1.68.1 (2 November 2026), with kernel-kit 9.6.2 | AWS's bulletin of 31 October expected fixed Bottlerocket AMIs from 2 November, and v1.68.1 shipped that day. v1.68.0 (27 October) didn't have the fix |
| AKS | Unclear | AKS's release tracker shows node image 202610.23.0 as current | Its kernel versions weren't confirmed. Node image 202610.16.1 (27 October) ran kernels below the fix for both Azure Linux and Ubuntu |
| Flatcar | Fixed (inferred) | Stable 4757.2.2 and later (4757.2.3 is current), LTS 4081.3.11 and later (4081.3.12) | Inferred from the kernel version |
| Talos | Fixed (inferred) | v1.14.3 and later (v1.14.5 is current) | Inferred from the kernel version |
| CentOS Stream | Pending | None | The newest Stream 9 and 10 kernels (28 October) don't name the CVE |
| Live patching | Oracle Ksplice, SUSE live patching and TuxCare KernelCare | Ksplice for UEK R6, R7 and R8. SUSE live patches for SLE 12 SP5 and 15 SP4 to SP7. KernelCare for Debian 13 at least | None found from Ubuntu Livepatch, RHEL kpatch or Amazon Linux |

Ubuntu is now the big gap. Its fixes were still in testing on 4 November, so Ubuntu hosts rely on the interim mitigations until the update is released. Red Hat and its rebuilds shipped between 1 and 3 November.

*Sources: vendor and distro pages and trackers checked on 30 October and again on 4 November 2026 (Debian security tracker and Freexian ELTS tracker, Ubuntu CVE tracker and Canonical blog, Red Hat CVE page, CSAF list, Bugzilla and bulletin RHSB-2026-016, Rocky Linux and AlmaLinux errata, SUSE CVE page and live patch advisories, Amazon Linux Security Center and AWS bulletin 2026-160-AWS, Oracle Linux CVE page, Microsoft update guide, Alpine security tracker, Fedora and Arch package indexes, TuxCare blog), Container-Optimized OS and GKE release notes, EKS AMI, Bottlerocket and AKS release notes and the AKS release tracker, Flatcar and Talos release notes, CentOS Stream package mirrors*

### Software that opens MPTCP listeners

The reporters demonstrated their exploit against an MPTCP listener, so what opens one decides which services you patch first. The bug is in the kernel, not in these programs. The fix is the same everywhere: patch the kernel, then reboot.

Upstream kernels default `net.mptcp.enabled` to 1. The setting is per network namespace, and every new namespace starts at 1. MPTCP is built in (`CONFIG_MPTCP=y`) on Ubuntu 22.04, 24.04 and 26.04, Debian bookworm and trixie, SLE 15 SP7 and 16.0, Azure Linux 3.0, Alpine linux-lts, Talos, and the Fedora and CentOS Stream common configs.

RHEL differs. Red Hat's RHEL 8 and 9 documentation says: "By default the MPTCP support is disabled in RHEL." The RHEL 10 guide also tells you to enable it, with no explicit default sentence. Red Hat's bulletin RHSB-2026-016 now says plainly that RHEL disables MPTCP in its default configuration, and that RHEL is affected anyway because MPTCP isn't a precondition. RHEL 8, 9 and 10 have had fixed kernels since 1 November.

Go matters most, because of one default. The Go 1.24 release notes say `ListenConfig` now uses MPTCP by default where supported (currently Linux only). The Go `godebug` documentation says that for Go 1.24 `multipathtcp` defaults to 2, listeners only, and that `multipathtcp=0` reverts to the old behavior. The values are 0 off, 1 listeners and dialers, 2 listeners only and 3 dialers only. Three rules decide what a given binary does:

- The default applies when the main module's go line is 1.24 or later. A binary whose module says go 1.23 or lower keeps MPTCP off.
- The `GODEBUG` environment variable overrides go.mod and `//go:debug` settings. An explicit `SetMultipathTCP(true)` in code overrides `GODEBUG`.
- If the kernel refuses MPTCP sockets (for example `net.mptcp.enabled=0` gives ENOPROTOOPT), Go silently falls back to plain TCP.

To read a compiled Go binary, see AM I AFFECTED? SELF-ASSESSMENT.

We read the go.mod of each project's latest release on 30 October 2026. All 18 declare go 1.24 or later with no godebug override that turns MPTCP off, so they open MPTCP listeners by default wherever the kernel allows it.

| Software | Release checked | What go.mod says |
| --- | --- | --- |
| Caddy | v2.11.7 | go 1.24 or later, no override |
| Traefik | v3.7.16 | go 1.24 or later, no override |
| Kubernetes | v1.37.2 | go 1.24 or later, `godebug default=go1.26`, which keeps the 1.24 and later default |
| k3s | v1.37.1+k3s1 | go 1.24 or later, no override |
| etcd | v3.7.3 | go 1.24 or later, no override |
| Prometheus | v3.15.1 | go 1.24 or later, no override |
| Grafana | v13.3.0 | go 1.24 or later, no override |
| Gitea | v28.2.0 | go 1.24 or later, no override |
| Vault | v2.2.1 | go 1.24 or later, no override |
| Consul | v2.1.0 | go 1.24 or later, no override |
| CoreDNS | v1.15.0 | go 1.24 or later, no override |
| Mattermost | v12.0.1 | go 1.24 or later, no override |
| NATS Server | v2.15.2 | go 1.24 or later, no override |
| Argo CD | v3.5.6 | go 1.24 or later, no override |
| MinIO | RELEASE.2025-10-15T17-29-55Z | go 1.24 or later, no override |
| Headscale | v0.29.6 | go 1.24 or later, no override |
| frp | v0.71.1 | go 1.24 or later, no override |
| Distribution (container registry) | v3.1.2 | go 1.24 or later, no override |

- This is derived from go.mod. We did not audit each program's code, and a program can opt out per socket.
- mptcp.dev (secondary) also lists Caddy since v2.10.0, and Traefik since v2.11.26 and v3.4.2, as MPTCP by default on the server side.
- Opt-in only: systemd sockets (`SocketProtocol=mptcp`), mptcpize and lighttpd (`server.network-mptcp` defaults to "disable") open MPTCP listeners only when someone configures them. Per mptcp.dev (secondary), HAProxy 3.1, NGINX 1.29.7, Apache, Envoy and Valkey 9 also need explicit configuration.
- Kubernetes and containers: kube-proxy and similar layer 4 forwarding pass packets, IP options included, to pods. Every pod network namespace starts with `net.mptcp.enabled=1` on upstream kernels, and a host sysctl doesn't change that. An ingress controller that terminates TCP shields the pods behind it, but it is itself exposed. Traefik, for example, is a Go program from the table.
- Go hasn't changed its default. Go issue 82717 was still undecided on 4 November. Ian Lance Taylor sees no reason to drop the MPTCP default over a security issue, and an MPTCP developer in the thread calls real-world success "very unlikely". The newest Go releases (go1.27.3 and go1.26.10, 20 October) keep `multipathtcp` as it was.
- Some projects are turning MPTCP off themselves. CoreDNS merged an MPTCP-off build default, not yet released on 4 November. Grafana Loki merged one and reverted it on 4 November. Pull requests for Caddy, Prometheus and NATS were closed unmerged, and the ones for etcd, Vault and Istio were still open.

*Sources: Go 1.24 release notes, Go godebug documentation, go.mod files of each project's latest release (read on 30 October 2026), mptcp.dev application list (secondary), Red Hat MPTCP documentation for RHEL 8, 9 and 10 and bulletin RHSB-2026-016, kernel MPTCP sysctl documentation, distribution kernel configurations, Go issue 82717 and the Go download index, and a GitHub search of the projects' pull requests (4 November 2026)*

---

## ATTACK TIMELINE

### How fast this moved

| When (UTC) | What happened |
| --- | --- |
| 2 October 2015 | Commit 079096f103fa ("tcp/dccp: install syn_recv requests into ehash table") is authored. It ships in Linux 4.4 in January 2016, and every kernel from 4.4 on carries the bug |
| 12 June 2021 | Commit c905dee62232 ("tcp: Migrate TCP_NEW_SYN_RECV requests at retransmitting SYN+ACKs.") is authored. It ships in Linux 5.14 and adds the request migration path |
| 25 September 2026 | The kernel CNA reserves the CVE ID |
| 29 September 2026, 21:43 | The first version of the fix is posted publicly to the netdev mailing list. Its commit message explains the use-after-free |
| 1 October 2026, 22:12 | Second version of the fix posted |
| 5 October 2026, 23:30 | Fix applied to the netdev net tree. The mainline commit is e3f33b0a1d89 |
| 11 October 2026 | Linux 7.2.10 and 6.18.56 released with the fix |
| 12 October 2026 | Linux 7.3-rc7 released with the fix |
| 15 October 2026 | Linux 6.12.113, 6.6.159, 6.1.190, 5.15.223 and 5.10.272 released with the fix |
| 15 October 2026, 12:08 | CVE published. NVD receives it at 13:17 |
| 15 October 2026, 18:32 | GitHub advisory GHSA-qp6h-4hvh-qqqc published (unreviewed, critical) |
| 16 October 2026 | Debian DSA-6568-1 (trixie). Oracle UEK errata ELSA-2026-500397, ELSA-2026-500398 and ELSA-2026-500399 |
| 17 October 2026 | Debian DLA-4841-1 (bookworm) |
| 18 October 2026 | Linux 7.3 released |
| 19 October 2026 | Oracle Ksplice updates for UEK R6, R7 and R8. A third party posts a proposed fix for the IPv6 sibling issue to netdev |
| 20 October 2026 | Azure Linux 3.0 kernel 6.6.159.1-1.azl3 reaches the production repository |
| 22 October 2026 | Debian DLA-4850-1 (bookworm linux-6.12) |
| 23 October 2026 | Flatcar stable 4757.2.2 and LTS 4081.3.11 ship fixed kernels (inferred) |
| 24 October 2026, 14:08 | kernel.org adds CVSS 3.1 9.8 to the CVE record |
| 24 October 2026 | Amazon ALAS2023-2026-3251 (kernel6.18). SUSE advisories SUSE-SU-2026:24386-1 and SUSE-SU-2026:24422-1 are dated this day, and SUSE's CVE page lists them on 29 October 2026 |
| 27 October 2026 | The reporters' write-up describes remote root command execution against servers with an MPTCP listener. EKS AL2023 AMI v20261026 ships fixed 6.12 and 6.18 kernels. The AKS node image of the same week does not |
| 28 October 2026 | Security press picks up the reporters' write-up |
| 29 October 2026 | Amazon ALAS2023-2026-3335 (kernel6.12) |
| 29 October 2026, 18:29 | The Hacker News publishes "Linux Kernel TCP Flaw With 9.8 CVSS Score Affects Ubuntu, Red Hat and Other Distributions" |
| 29 October 2026, 20:17 | Go proposal issue 82717, "proposal: net: Disable MPTCP by default", is opened |
| 29 October 2026, 22:56 | Ubuntu tracker updated with staged fixes |
| 29 October 2026, 23:34 | Go security team announcement on golang-announce |
| 29 to 30 October 2026 | Eleven GitHub repositories named after the CVE appear. None is verified |
| 30 October 2026, 00:21 | The Go announcement is forwarded to oss-security |
| 30 October 2026, 02:08 | CISA's ADP container adds the oss-security link to the CVE record |
| 30 October 2026, 06:30 | Data cut-off for version 1.0 of this analysis |
| 30 October 2026 | Amazon Linux fixes its AL2023 6.1 kernel (ALAS2023-2026-3365) and its AL2 kernels (ALAS2-2026-4065 and the 5.4, 5.10 and 5.15 extras). Linux 7.3.1, 6.18.60, 6.12.115, 6.6.161, 6.1.191, 5.15.224 and 5.10.273 are released. Container-Optimized OS names the fix in cos-133-19999-44-174. CERTs in the Netherlands (NCSC-2026-0461), Canada (AV26-1108) and France (CERTFR-2026-AVI-1432) issue advisories. AlmaLinux posts interim mitigations. Red Hat publishes bulletin RHSB-2026-016 (16:03), and The Hacker News dates its nftables rule for IPv4 TCP packets with IP options to the same day. BleepingComputer reports "no confirmed reports" of exploitation |
| 30 October 2026, 09:05 | An oss-security post points out that `net.mptcp.enabled=0` turns MPTCP off system-wide |
| 30 to 31 October 2026 | On Go issue 82717, Ian Lance Taylor argues against dropping the MPTCP default |
| 31 October 2026, 05:15 | AWS bulletin 2026-160-AWS: Amazon Linux kernels available, EKS and ECS AMIs fixed, Global Accelerator drops packets with IP options, and "no evidence" the bug has been used |
| 31 October 2026, 16:01 | An oss-security post suggests `init_on_free=1` as an extra stopgap |
| 1 November 2026 | Red Hat ships RHSA-2026:93414, 93412 and 93413 for RHEL 8, 9 and 10. Linux 7.2.15 ends the 7.2 line, and 7.4-rc1 is released |
| 2 November 2026 | Oracle ships Red Hat compatible kernel errata (ELSA-2026-93414, -93412 and -93413) and new UEK errata. AlmaLinux's fixed kernels reach its repositories. Fortinet publishes PSIRT FG-IR-26-188. Bottlerocket v1.68.1 ships the fix (17:44). Canonical says Ubuntu's fixes are in -proposed for testing (21:00) |
| 3 November 2026 | A CIQ kernel engineer replies on oss-security that `init_on_free=1` doesn't help (04:46). SUSE publishes live patch advisories for SLE 15 SP7 (SUSE-SU-2026:5058-1 and 5059-1). FortiGuard lists an IPS signature for the CVE. Eric Dumazet posts the IPv6 sibling fix to netdev (09:00). Rocky Linux ships RLSA-2026:93414, 93412 and 93413 (12:01 to 12:10). Ubuntu raises its priority to critical (12:24). HKCERT issues bulletins, and The Hacker News reports Red Hat's fixes and its move to 9.8 |
| 4 November 2026 | Red Hat updates bulletin RHSB-2026-016. A GitHub search finds 71 repositories that mention the CVE. Previdian still says "No Exploitation Yet" |
| 4 November 2026, 14:00 | Data cut-off for version 1.1 |

Critical insight: the fix and its technical explanation sat in public on netdev from 29 September 2026. That is 16 days before the CVE was published and 28 days before the reporters' write-up. The commit message of the first version explains the use-after-free, so the bug was readable on the list four weeks before the exploit story broke. The first fixed releases came on 11 October 2026. Red Hat shipped 17 days after the CVE was published, and Ubuntu was still testing on day 20. For an internet-facing server with an MPTCP listener, "we'll patch it next window" isn't a plan.

*Sources: kernel.org ChangeLog files, releases page and CVE record, the netdev mailing list and its marc.info archive, kernel commit history, NVD, GitHub advisory database, Debian, Oracle Linux, Amazon Linux, SUSE, Red Hat, Rocky Linux, AlmaLinux, Microsoft, Flatcar, EKS and Bottlerocket release notes and advisories, Container-Optimized OS release notes, AWS bulletin 2026-160-AWS, Fortinet PSIRT, the reporters' write-up, Go security team announcement, Go issue 82717, The Hacker News (29 October and 3 November 2026), BleepingComputer (30 October 2026), Ubuntu CVE tracker and Canonical blog, oss-security, CISA ADP container, NCSC-NL, CCCS, CERT-FR and HKCERT advisories, Previdian, GitHub repository search*

### Who's attacking

No exploitation in the wild has been reported, so there is nobody to attribute. No threat actor is known to be using the bug. Here is what each source said by 4 November:

| Source | What they said or showed | Confidence |
| --- | --- | --- |
| The reporters' write-up (27 October 2026, updated 28 October 2026) | Describes an exploit that lets a remote attacker with no credentials and no user interaction run arbitrary commands as root on Linux servers with an MPTCP listener. Stage 1 defeats kernel address randomization (KASLR) remotely by leaking a kernel pointer through the over-read in the SYN-ACK. Stage 2 ends with an attacker-chosen shell command running as root. A lost race only fails the handshake, so an attacker can retry indefinitely. The proof of concept took 48 minutes to leak a kernel pointer and another 5 minutes to reach command execution. It says the bug is patched upstream and backported to all maintained stable branches. It names no tested kernel versions or distributions and doesn't explain why MPTCP is needed. No exploit code was published and no release was announced. On 3 November The Hacker News said the code was still unpublished | The reporters' own account. No code and no tested versions shown |
| Go security team (golang-announce, 29 October 2026, 23:34 UTC, forwarded to oss-security on 30 October 2026) | The demonstrated exploit requires an MPTCP listener. The underlying bug is not specific to MPTCP, and systems with no MPTCP listener may be vulnerable to similar attacks. Go 1.24 and later enable MPTCP by default for listen sockets on Linux. Disabling MPTCP program by program is "a fragile mitigation", and the best fix is a patched kernel. It is premature to change Go's defaults, and discussion continues in Go issue 82717 | Statement from the Go security team. No test results shown |
| Go issue 82717 ("proposal: net: Disable MPTCP by default") | Opened 29 October 2026 by a community member and still undecided on 4 November. A Go team member said early on that nobody knows whether remote code execution is possible without an MPTCP listener, and that dropping IPv4 TCP packets that carry IP options "may suffice", which is unconfirmed. Ian Lance Taylor later argued against dropping the default, and an MPTCP developer called real-world success "very unlikely" | Public discussion, nothing verified |
| Red Hat (bulletin RHSB-2026-016, last updated 4 November) | Having MPTCP enabled is not a precondition, and disabling it is "not a complete mitigation". Recommends an nftables filter for IPv4 TCP packets with IP options, which reduces exposure but "cannot fully prevent" exploitation and doesn't cover pod-to-pod traffic in OpenShift | Vendor statement. No test results shown |
| A CIQ kernel engineer (oss-security, 3 November) | `init_on_free=1` does nothing meaningful against this CVE, because the remote KASLR defeat leaks pointers from live slab objects. The IP-options filter misses traffic between containers on the same host | Code analysis, no reproduction |
| Exploitation reports | None reported. Rapid7 lists `exploited_in_wild` as false, Wiz and Feedly show no evidence, Previdian says "No Exploitation Yet" (4 November), AWS has "no evidence" (31 October), Fortinet's PSIRT lists it as not known exploited (2 November), and BleepingComputer found "no confirmed reports" (30 October) | Negative, and weak evidence |
| CISA | Not in KEV (catalog 2026.11.03). No alert. CISA's ADP container added the Go announcement link to the CVE record on 30 October 2026 (02:08 UTC) | Negative |
| GitHub | 71 repositories mention the CVE on 4 November, up from 11 on 30 October. Descriptions include checkers, mitigations, a trigger that says it does no code execution, and a "lab root-shell kit" that says it is not a stock remote exploit. The Hacker News (3 November) says the proof-only code it saw does not implement code execution | Not verified. Treat as untrusted |
| National CERTs | NCSC-NL (NCSC-2026-0461), the Canadian Centre for Cyber Security (AV26-1108, no exploitation claim) and CERT-FR (CERTFR-2026-AVI-1432) issued advisories on 30 October, and HKCERT bulletins followed on 3 November. CISA and NCSC UK had nothing in their feeds up to 3 November. BSI, ACSC, CERT-In, JPCERT/CC and CERT-EU couldn't be checked properly | Advisories only, no attack data |
| Cloud providers | AWS bulletin 2026-160-AWS (31 October): no evidence of use, Amazon Linux kernels and the EKS and ECS images fixed, Bottlerocket images expected from 2 November, and Global Accelerator drops packets with IP options. No Google Cloud or GKE bulletin names the CVE. Microsoft's update guide lists it for Azure Linux with customer action required | Advisories only, no attack data |
| Security vendors | Fortinet published PSIRT FG-IR-26-188 on 2 November, and FortiGuard lists an IPS signature, Linux.Kernel.tcp_v4_syn_recv_sock.Use.After.Free, from 3 November. Tenable lists 73 plugins, and Rapid7 and Snyk have entries. There is no Emerging Threats Open or Snort community rule and no nuclei template | Detection content, no attack data |
| Press | The Hacker News (29 October and 3 November), BleepingComputer, CSO Online and heise (30 October). Nothing in The Register or LWN | Secondary sources |

Absence of reports is weak evidence, and some of the feeds above couldn't be read in full, so "no exploitation" only means what the readable sources say. There is no IP list to give you. The only published attack pattern is the reporters' own: many handshakes from one source over tens of minutes, with Record Route or Timestamp options and retransmitted SYNs. Skip the repositories too: nobody has verified them, and running unknown proof-of-concept code is a common way to get compromised. To find out whether you're exposed, use the checks in AM I AFFECTED? SELF-ASSESSMENT.

*Sources: the reporters' write-up, Go security team announcement (golang-announce and oss-security), Go issue 82717, Red Hat bulletin RHSB-2026-016, oss-security (3 November 2026), Rapid7, Wiz, Feedly, Previdian, AWS bulletin 2026-160-AWS, Fortinet PSIRT, Tenable, Snyk, nuclei-templates, Emerging Threats Open and Snort community rules, CISA KEV feed, alerts and ADP container, GitHub repository search, NCSC-NL, CCCS, CERT-FR, HKCERT and NCSC UK, Microsoft update guide, Google Cloud and GKE bulletins, The Hacker News (29 October and 3 November 2026), BleepingComputer (30 October 2026)*

### Global impact statistics

- **No count exists** of exposed internet-facing Linux hosts, of hosts with MPTCP listeners or of unpatched installs. No public exposure counts exist, and this analysis gives none. A count of kernel versions couldn't size the exposure anyway, because it depends on which listeners a host runs and whether IP options reach them.
- **0.0076** is the EPSS score (55.3rd percentile) on 3 November 2026, up from 0.00388 on 29 October. It is a score for the chance of exploitation, not a count of exposed hosts.
- **Not listed** in CISA KEV (catalog 2026.11.03), and no source checked reports exploitation in the wild.
- **71** GitHub repositories mentioned the CVE on 4 November, up from 11 on 30 October. A proxy for attention, not exposure. None is verified.
- **73** Tenable plugins listed the CVE on 4 November.
- **18** common Go servers checked all open MPTCP listeners by default wherever the kernel allows it (see Software that opens MPTCP listeners). That sizes the software, not the exposure.

*Sources: FIRST EPSS API, CISA KEV feed, GitHub repository search, Tenable, go.mod files of each project's latest release, the reporters' write-up, Go security team announcement, The Hacker News (29 October 2026), vendor and distro advisories*

---

## AM I AFFECTED? SELF-ASSESSMENT

The checks below are manual and read-only. Run the host commands as root where a comment says so, or they will miss other users' processes.

### Quick 3-minute assessment

**STEP 1: Which kernel does each host run? (1 minute)**

```bash
# Running kernel release. Compare it with the fixed versions
uname -r

# Debian and Ubuntu: version of the installed kernel package that matches the running kernel
dpkg -s linux-image-$(uname -r) | grep '^Version'

# RHEL family, Fedora, Amazon Linux (kernel6.12, kernel6.18), Oracle (kernel-uek), SUSE (kernel-default): every installed kernel package
rpm -qa 'kernel*' | sort
```

The package list shows every installed kernel, old ones included. Only the one that `uname -r` names is running.

Containers share the host kernel and have none of their own, so the kernel that counts is the one on the host or the Kubernetes node. On a managed Kubernetes service, the node image decides it. On 4 November the EKS AL2023 AMI v20261031 and Bottlerocket v1.68.1 carried fixed kernels. AKS had rolled out node image 202610.23.0, whose kernel versions we couldn't confirm. Where the fix comes from, in the RISK DASHBOARD, has every node image state we found.

Inventories miss some places, so look there too: cloud images and virtual machines nobody owns any more, test and staging servers that face the internet, build agents, Kubernetes node pools, and products that run Linux inside (ask the vendor). Hosts with no listening TCP port that an untrusted IPv4 network can reach are less exposed, so start with the ones that have one.

*Sources: EKS AMI, AKS and Bottlerocket release notes, AWS bulletin 2026-160-AWS, AKS release tracker (checked on 30 October and 4 November 2026)*

---

**STEP 2: Does this kernel carry the fix? (30 seconds)**

Start with the version-number trap, because it fools scanners and people alike. Linux fixes arrive upstream as point releases, but most servers run a vendor kernel, and vendors backport fixes into their own numbering. Oracle's UEK R6 5.4.17-2136.360.3.1 and SUSE's 5.14.21-150500.55.195.1 carry the fix, although upstream has no fix for 5.4 or 5.14. Ubuntu and Red Hat use build numbers of their own, which don't map to upstream point releases. Compare a vendor kernel with the vendor's fixed build. Use the upstream numbers only for kernels you build yourself and for distros that follow upstream point releases.

**Interpretation:**

- Upstream point releases (kernels you build, and distros that follow them: Debian, Arch, Fedora and Alpine): the upstream number decides. Debian shows it in the package version, for example 6.1.190-1. Fixed from 7.3 (7.3-rc7 and later), 7.2.10, 6.18.56, 6.12.113, 6.6.159, 6.1.190, 5.15.223 or 5.10.272, each within its own line. Anything older in those lines is vulnerable. For Arch, Fedora and Alpine the status is inferred: we compared their kernel versions with the upstream fixed versions, and no vendor notice names the CVE.
- The newest releases on 4 November 2026, per kernel.org, are mainline 7.4-rc1, stable 7.3.1, and longterm 6.18.60, 6.12.115, 6.6.161, 6.1.191, 5.15.224 and 5.10.273. The 7.2 line ended with 7.2.15 on 1 November. kernel.org projects end of life for 5.15 and 5.10 in December 2026.
- No upstream fix exists for 5.4 and older, or for end-of-life lines that aren't longterm (for example 7.1, 7.0 and 6.19). Those kernels are fixed only where a vendor backported the patch.
- Vendor kernels (Ubuntu, the RHEL family, SUSE, Oracle, Amazon Linux, Azure Linux): the vendor's package version decides. What each platform has published is in Where the fix comes from, in the RISK DASHBOARD. On 4 November Ubuntu and CentOS Stream had no released fixed package, and OpenShift 4 was still listed as affected.
- Not affected: kernels older than 4.4, RHEL 6 and 7 (the vulnerable code isn't present), Ubuntu 14.04 and SLE 11 SP4.

Fixed: go to STEP 4: Is the fixed kernel actually running? Vulnerable or unsure: go to STEP 3: How exposed is it?

*Sources: kernel.org ChangeLog files and release list, the CVE record, Debian, Ubuntu, Red Hat, SUSE, Oracle and Amazon Linux security pages, Fedora, Arch and Alpine package versions (checked on 30 October and 4 November 2026)*

---

**STEP 3: How exposed is it? (1 minute)**

The bug is server side: the kernel runs the vulnerable code for incoming connections to listening TCP sockets, over IPv4. Outgoing client connections don't use it. A host is exposed when an attacker can reach a listening TCP port over IPv4 with the attacker's IP options intact. No login and no user interaction are needed.

```bash
# All TCP listening sockets, with the processes behind them (run as root)
ss -tlnp
```

**Interpretation:**

- A listener on `0.0.0.0` takes IPv4 connections. So does a listener on `[::]` that doesn't set IPV6_V6ONLY (a dual-stack socket): the kernel hands IPv4 packets that arrive there to the IPv4 code. Native IPv6 connections don't take the first path, because the IPv6 code copies the options. Treat a wildcard IPv6 listener as reachable over IPv4 unless you know its program sets IPV6_V6ONLY.
- A listener on `127.0.0.1` or `::1` can't be reached from outside. A listener on an internal address is exposed to everyone who can reach that network, partners and VPN users included.
- Security groups and network ACLs can't match IP options, so a port they allow stays reachable with the options intact. AWS says Global Accelerator drops IPv4 packets that carry IP options, but no AWS, Google Cloud or Azure documentation says the same of their virtual networks, and AWS's own interim rules filter at the instance. Treat the network as unknown.
- A proxy that terminates TCP (the Cloudflare proxy, AWS ALB, CloudFront, any reverse proxy) keeps the attacker's IP options away from the origin's kernel. AWS's bulletin says customers behind ALB, CloudFront, API Gateway and NLB TLS listeners don't receive TCP connections from untrusted sources directly when they follow its best practices. It holds only while the origin can't be reached directly. Lock the origin firewall to the proxy's IP ranges. The proxy's own kernel is its operator's problem, and a reverse proxy you run yourself is exposed like any other server. Services published only through outbound tunnels (for example Cloudflare Tunnel) have no internet-facing listener.
- L4 passthrough load balancers (AWS NLB with TCP listeners, Google Cloud passthrough network load balancers) forward packets, and no documentation says they strip IP options. Treat services behind them as exposed. The same goes for kube-proxy and similar L4 forwarding, which pass packets on to pods with the IP options included.

Next, the MPTCP and request migration settings:

```bash
# MPTCP and request migration settings
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req

# MPTCP listening sockets in the current network namespace, with processes (run as root)
ss -Mlnp

# Reuseport BPF programs that could migrate requests (run as root)
bpftool prog show | grep sk_reuseport
```

- `net.mptcp.enabled = 1` means MPTCP sockets can be created. Upstream kernels default to 1, and the setting is per network namespace: every new namespace starts at 1. CONFIG_MPTCP=y on Ubuntu 22.04, 24.04 and 26.04, Debian bookworm and trixie, SLE 15 SP7 and 16.0, Azure Linux 3.0, Alpine linux-lts, Talos, and the Fedora and CentOS Stream common configs. Red Hat's documentation for RHEL 8 and 9 says "By default the MPTCP support is disabled in RHEL." The RHEL 10 guide also tells you to enable it, with no explicit default sentence.
- A row from `ss -Mlnp` is a process that accepts MPTCP connections right now. The demonstrated code execution path needs one. The setting is checked only when a socket is created, so a listener opened earlier keeps accepting MPTCP after you change the sysctl, until its service restarts.
- `net.ipv4.tcp_migrate_req = 1` turns on the second path, request socket migration, which exists only in Linux 5.14 and later. The default is 0. A BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program migrates requests whatever the sysctl says. `bpftool` lists sk_reuseport programs but can't show whether one is the migrating kind, so treat any sk_reuseport program as a candidate.

Then any Go programs on the host:

```bash
# Go build info: Go version and compiled-in GODEBUG defaults (needs a Go toolchain; a directory is scanned recursively)
go version -m /path/to/binary
```

- Go programs whose module declares go 1.24 or later enable MPTCP by default for listen sockets on Linux. The default applies when the main module's go line is 1.24 or later. A binary whose module says go 1.23 or lower keeps MPTCP off.
- The "build DefaultGODEBUG=..." line appears only when it is not empty. A binary whose module declares go 1.24 or later, and shows no `multipathtcp=0` there, opens MPTCP listeners by default.
- The GODEBUG environment variable overrides go.mod and `//go:debug` settings. An explicit `SetMultipathTCP(true)` in code overrides GODEBUG.
- If the kernel refuses MPTCP sockets (`net.mptcp.enabled=0` gives ENOPROTOOPT), Go silently falls back to plain TCP.

We read the go.mod of each project's latest release on 30 October 2026. All of these declare go 1.24 or later with no godebug override that turns MPTCP off, so they open MPTCP listeners by default wherever the kernel allows it: Caddy v2.11.7, Traefik v3.7.16, Kubernetes v1.37.2, k3s v1.37.1+k3s1, etcd v3.7.3, Prometheus v3.15.1, Grafana v13.3.0, Gitea v28.2.0, Vault v2.2.1, Consul v2.1.0, CoreDNS v1.15.0, Mattermost v12.0.1, NATS Server v2.15.2, Argo CD v3.5.6, MinIO RELEASE.2025-10-15T17-29-55Z, Headscale v0.29.6, frp v0.71.1 and Distribution (the container registry) v3.1.2. Kubernetes declares "godebug default=go1.26", which keeps the 1.24 and later default. This comes from go.mod only. We didn't audit each program's code, and a program can opt out per socket. The mptcp.dev application list (secondary) also names Caddy since v2.10.0, and Traefik since v2.11.26 and v3.4.2, as MPTCP by default on the server side.

Other servers need explicit configuration to listen on MPTCP: systemd sockets (`SocketProtocol=mptcp`), mptcpize, and lighttpd (`server.network-mptcp` defaults to "disable"). Per the same list (secondary), HAProxy 3.1, NGINX 1.29.7, Apache, Envoy and Valkey 9 need explicit configuration too.

Last, the containers:

```bash
# The same listener check inside a container's network namespace (run as root)
nsenter -t <container-pid> -n ss -Mlnp
```

Use the process ID of any process in the container, as the host sees it (`ps` on the host lists it). Every pod or container network namespace starts with `net.mptcp.enabled = 1` on upstream kernels, and a host sysctl doesn't change that, so check the containers as well as the host.

| What you found | Priority |
| --- | --- |
| Internet-facing Linux server that takes inbound IPv4 TCP connections directly (dual-stack listeners count), on an unfixed kernel, with an MPTCP listener or a Go service whose module declares go 1.24 or later | CRITICAL. Patch and restart first, today |
| Internet-facing Linux server that takes inbound IPv4 TCP connections directly, on an unfixed kernel, with no MPTCP listener found | CRITICAL. Patch and restart today, right after the row above. Nobody has publicly shown code execution without an MPTCP listener, but the Go security team says similar attacks may work |
| Everything else on an unfixed kernel: internal-only servers, servers behind a TCP-terminating proxy with a locked origin, and any host where you can't show that no listener is reachable from an untrusted network | HIGH. Patch this week |

Container hosts and Kubernetes nodes count as internet-facing when their pods or services are reachable from untrusted networks.

*Sources: kernel.org CVE record and fix commit message, Linux kernel source (net/ipv6/tcp_ipv6.c), Linux kernel MPTCP and IP sysctl documentation, kernel configuration of Ubuntu, Debian, SUSE, Azure Linux, Alpine, Talos, Fedora and CentOS Stream, Red Hat documentation for RHEL 8, 9 and 10, Go 1.24 release notes and godebug documentation, Go security team announcement, go.mod files of the releases named above (30 October 2026), mptcp.dev application list (secondary), AWS, Google Cloud, Azure and Cloudflare documentation*

---

**STEP 4: Is the fixed kernel actually running? (30 seconds)**

```bash
# Running kernel. A fixed package on disk changes nothing until the host restarts into it
uname -r

# Is a reboot still pending?
# Debian and Ubuntu
cat /var/run/reboot-required
# RHEL family (needs dnf-utils or yum-utils)
needs-restarting -r
# SUSE
zypper needs-rebooting
```

A kernel update installs the new kernel next to the old one, and the old one keeps running until the host restarts. The release in `uname -r` appears in the name of its package. If a newer kernel package is installed and `uname -r` names an older one, the host has not restarted into it, so restart it. A container host or Kubernetes node works the same way: containers use the node's kernel, so rebuilding or pulling container images changes nothing. The node has to restart, or be replaced by a node image that carries the fix. Oracle Ksplice is the only live patch we confirmed for this CVE (UEK R6, R7 and R8). A host patched that way doesn't need the restart, but confirm the update is applied with Oracle's own tooling.

*Sources: Oracle Linux security pages and Ksplice updates, Ubuntu, Red Hat, SUSE and Amazon Linux security pages (checked on 30 October 2026)*

---

### Full vulnerability checklist

**You are VULNERABLE if ALL of these are true:**

- [ ] The host runs a Linux kernel from 4.4 up to the fixed version, and the kernel doesn't carry the fix. For kernels that follow upstream, that means older than 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10 or 7.3 in its line, or a kernel from 5.4 or older, or from an end-of-life line that isn't longterm, with no vendor backport. For vendor kernels, it means a package older than the vendor's fixed build, or a platform with no fixed build yet
- [ ] A TCP service listens on the host and an untrusted party can reach it over IPv4: the internet, a partner network, a VPN. A dual-stack listener counts
- [ ] The attacker's IP options reach the host: no proxy that terminates TCP sits in front of it, and nothing on the path drops packets that carry IP options

**Your risk is higher if ANY of these also apply:**

- [ ] The host has an MPTCP listener (`ss -Mlnp` shows one). That is the only path with a published demonstration of root command execution, with no credentials and no user interaction
- [ ] A Go service whose module declares go 1.24 or later listens on the host and nothing turned MPTCP off for it. It opens MPTCP listeners by default
- [ ] `net.ipv4.tcp_migrate_req` is 1, or a BPF reuseport program that migrates requests runs on the host (the second path, Linux 5.14 and later)
- [ ] The service sits behind an L4 passthrough load balancer, kube-proxy or any other forwarding that passes packets on with their IP options
- [ ] The origin answers direct connections, so a proxy or CDN in front of it can be skipped
- [ ] The host is a container host or Kubernetes node whose pods are reachable from untrusted networks (every new network namespace starts with MPTCP enabled on upstream kernels)
- [ ] The host runs on a platform with no released fix yet: Ubuntu, OpenShift 4, CentOS Stream 9 or 10, or an AKS node image whose kernel you can't confirm
- [ ] The host runs a kernel that will never get an upstream fix and has no vendor backport: 5.4 and older, end-of-life lines such as 7.1, 7.0 and 6.19, Debian stretch and buster
- [ ] The host holds credentials, signing keys or customer data. A successful attacker runs commands as root

Nothing on the second list is a reason to skip the update. The upstream fix is two one-line changes, and every maintained kernel line has it.

*Sources: kernel.org fix commit and ChangeLog files, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle and Microsoft security pages (checked on 30 October and 4 November 2026)*

---

### You are SAFE if:

- [ ] Every Linux host you run is on a kernel at or above the fixed version for its line (5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10 or 7.3), or on a vendor kernel at or above the vendor's fixed build
- [ ] Every patched host was restarted, and `uname -r` shows the fixed kernel (a package on disk doesn't count)
- [ ] Container hosts and Kubernetes nodes were restarted or replaced with a fixed node image (a rebuilt container image doesn't count)
- [ ] Your managed platform has confirmed in writing which kernel your nodes or instances run, and a node reports the version you expect
- [ ] No listening TCP port on any host is reachable from an untrusted IPv4 network, and you checked dual-stack listeners, test servers and container hosts before saying so
- [ ] Your services reach the internet only through a proxy that terminates TCP or an outbound tunnel, and the origin firewall allows only the proxy's IP ranges (AWS says customers behind its TCP-terminating services don't receive untrusted TCP connections directly)
- [ ] The only Linux you run is RHEL 6 or 7, or kernels older than 4.4 (not affected)

IPv6-only services (IPv6-only sockets, or dual-stack sockets that receive no IPv4) are less exposed to the first path, but that is not the same as safe. The CVE text says tcp_v6_reqsk_destructor() has the same migration issue with ipv6_opt, which only CALIPSO sets, and that a separate patch will fix it. A maintainer posted that patch on 3 November, and it was still under review on 4 November, with no CVE.

**IMPORTANT:** Closing the MPTCP path, filtering IP options and changing Go settings do not fix the bug. Only a patched kernel does, and only after the host restarts into it. Turning MPTCP off closes the demonstrated path only: plain TCP stays exposed. Red Hat says dropping TCP packets that carry IP options reduces exposure but cannot fully prevent exploitation.

A clean scanner report still proves little. NVD still shows the record as Received with no score of its own, Debian has assigned no urgency, the GitHub advisory is unreviewed and the Alpine tracker has no package data. Ubuntu has no released kernel for a scanner to match. A scanner that goes by the upstream number can also misjudge a vendor kernel that carries a backport. Check the running kernel with the commands above.

*Sources: kernel.org ChangeLog files and the CVE record, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle and Microsoft security pages, Red Hat bulletin RHSB-2026-016, NVD, GitHub Advisory Database, Alpine security tracker, the netdev list, Linux kernel and Go security team documents (checked on 30 October and 4 November 2026)*

---

## PROTECTION ROADMAP

### For non-technical executives

#### HOUR 1: Emergency assessment

**Immediate actions checklist:**

- [ ] Get IT, the engineering leads and your hosting and cloud providers on one call
- [ ] Ask: "Which of our Linux servers accept connections straight from the internet? Websites, APIs, mail, remote access, container and Kubernetes hosts?"
- [ ] Get the kernel version of each one, and ask for the version that is running, not the one that is installed (IT runs the Quick 3-minute assessment). A patched kernel does nothing until the server restarts
- [ ] Ask every provider that runs Linux for you, in writing, which kernel your workloads use and whether it has the fix
- [ ] Flag any internet-facing server on a platform with no released fix yet (Ubuntu above all) or on an end-of-life system
- [ ] Approve emergency maintenance, including restarts during business hours and taking a service offline if it comes to that
- [ ] Tell legal, compliance and your cyber insurer that you're responding

**Decision points:**

- Everything on a fixed kernel and restarted: document it and move to WEEK 1: Verification and assessment.
- Internet-facing servers where the vendor has shipped a fix: approve patching and a restart today. Servers that run Go programs or accept MPTCP connections (IT knows which) go first.
- Servers on a platform with no released fix yet (Ubuntu, OpenShift 4): approve the interim measures in For technical teams, and ask the vendor in writing for a date. Red Hat recommends one of those measures, dropping network packets that carry IP options, but says it can't fully prevent an attack.
- Servers on end-of-life systems, where no fix is coming: approve a move to a supported system, or take the service off the internet until it's done.

---

#### DAY 1: Emergency response

**Executive decision checklist:**

- [ ] Approve maintenance windows. Every affected server has to restart, and container clusters have to restart or replace their servers in batches, so plan for short interruptions
- [ ] Decide what to do about servers that can't take a fixed kernel today. That means platforms with no released vendor fix yet (Ubuntu, OpenShift 4) and end-of-life systems, which will never get one:
    - [ ] **Option A:** Move the service to a platform that already has a fixed kernel (safest)
    - [ ] **Option B:** Take internet-facing services offline, or close them to the public internet, until the fix arrives
    - [ ] **Option C:** Interim controls while you wait: dropping packets that carry IP options, and switching off MPTCP (leaves the most risk behind: Red Hat says the packet filter reduces exposure but can't fully prevent an attack, and switching off MPTCP closes only the one demonstrated path)
- [ ] Communication plan:
    - [ ] Brief the board if you're publicly traded
    - [ ] Prepare a customer notice in case a service has to go offline
    - [ ] Tell your cyber insurer
    - [ ] Ask legal for a compliance read
- [ ] Resources:
    - [ ] Approve overtime or outside help if the team is stretched
    - [ ] Call in your incident response retainer if you have one

---

#### WEEK 1: Verification and assessment

**Follow-up checklist:**

- [ ] Confirm, with evidence, that every internet-facing Linux server runs a fixed kernel and has restarted. Evidence means output from the server (the running kernel version), not a package list or a ticket
- [ ] Review logs back to at least 29 September 2026, when the fix and its technical explanation first appeared on a public mailing list. That is 16 days before the CVE was published and 28 days before the reporters' write-up. No source we checked reports attacks in the wild, but clean logs prove little: a lost race leaves no crash, and a successful exploit is designed not to crash
- [ ] Re-check vendor and platform advisories. On 4 November Ubuntu's fixes were still in testing, OpenShift 4 was still listed as affected, the AKS node image's kernel couldn't be confirmed, and Google Cloud had no bulletin. AWS published bulletin 2026-160-AWS on 31 October, and Microsoft's update guide lists the CVE for Azure Linux with customer action required
- [ ] Ask your scanner vendor how it judges vendor kernels. NVD still has no score of its own, the Alpine tracker has no package data and Ubuntu has no notice, so a clean scan proves little
- [ ] Rotate secrets on any server that showed suspicious activity: credentials, keys and tokens stored on it. A successful attacker runs commands as root
- [ ] Hold a post-incident review with the technical teams
- [ ] Compliance:
    - [ ] Check notification duties if you found any sign of compromise
    - [ ] Keep timestamped records of everything you did
    - [ ] Preserve evidence
    - [ ] Get legal advice before you conclude "no breach"

---

#### MONTH 1: Strategic planning

**Lasting improvements:**

- [ ] Retire end-of-life systems for good (Amazon Linux 2 is marked end of support, Debian stretch and buster are end of life, the 7.2 kernel line ended on 1 November, and upstream has no fix for 5.4 and older kernels). Plan the move off the 5.15 and 5.10 kernels too: kernel.org projects their end of life for December 2026
- [ ] Keep a live inventory of every Linux host, including container hosts, Kubernetes nodes and cloud images, with the running kernel, who supplies it and whether it accepts MPTCP connections
- [ ] Subscribe to your distro's security feed and your cloud provider's bulletins, and, if you run Go services, the Go security announcements
- [ ] Agree a restart policy: how fast a kernel fix reaches production, who may approve an emergency restart, and when the maintenance windows are
- [ ] Put internet-facing services behind a proxy that terminates TCP, and lock origin servers to the proxy's IP ranges
- [ ] Turn MPTCP off wherever no service needs it, and review which services open MPTCP listeners
- [ ] Ask your hosting and cloud providers whether their networks drop packets with IP options. AWS says Global Accelerator does, but no AWS, Google Cloud or Azure documentation says their virtual networks do, so treat the answer as unknown until they confirm it
- [ ] Add detection for commands that the kernel itself starts (DETECTION & FORENSICS says how)
- [ ] Check what your scanner sees: does it know vendor kernel builds, or only upstream version numbers?
- [ ] Review hosting contracts for patch timelines and notification duties
- [ ] Run a tabletop exercise based on this incident

*Sources: kernel.org release data and the CVE record, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle and Microsoft security pages, Go security team announcement, AWS, Google Cloud and Azure documentation and bulletins (checked on 30 October 2026)*

---

### For technical teams

#### IMMEDIATE ACTIONS (Hour 1-2)

**Phase 1: Assessment and inventory**

**Checklist:**

- [ ] Find every Linux host that accepts inbound TCP (servers, virtual machines, cloud instances, container hosts, Kubernetes nodes, appliances that run Linux)
- [ ] Record the running kernel, the installed kernel package and who supplies it (a vendor, or you)
- [ ] Record whether the host accepts inbound IPv4 TCP from untrusted networks (dual-stack listeners included), and whether a proxy that terminates TCP sits in front with the origin locked down
- [ ] Record MPTCP: the value of `net.mptcp.enabled`, every MPTCP listener and the process behind it
- [ ] Record Go services: the Go version and the `multipathtcp` default compiled into each binary
- [ ] Record `net.ipv4.tcp_migrate_req` and any sk_reuseport BPF program
- [ ] Record the node image version of every Kubernetes node
- [ ] Put internet-facing hosts with MPTCP listeners or Go services first, then everything else that accepts inbound IPv4 TCP

**Commands for assessment:**

```bash
# Which distribution and release is this host?
cat /etc/os-release

# Running kernel release
uname -r

# Debian and Ubuntu: every installed kernel image package
dpkg -l 'linux-image*' | grep '^ii'

# RHEL family, Fedora, Amazon Linux, Oracle, SUSE: every installed kernel package
rpm -qa 'kernel*' | sort

# Listening TCP sockets, then MPTCP listeners, with processes (run as root)
ss -tlnp
ss -Mlnp

# MPTCP and request migration settings
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req

# Reuseport BPF programs that could migrate requests (run as root)
bpftool prog show | grep sk_reuseport

# Firewall rules already on the host, before you add the interim filter (run as root)
nft list ruleset
iptables -t raw -L -n -v
```

For bigger estates, collect the running kernel (the output of `uname -r`) from every host through your inventory or configuration management tool, not the installed package list alone. A package list says what is installed, and this bug is fixed only in what is running.

Don't test your hosts with proof-of-concept code from public repositories. By 4 November, 71 GitHub repositories mentioned the CVE, up from 11 on 30 October. None is verified, and running unknown code is a common way to get compromised.

**Document your findings:**

```
Host / node / image:
Distribution and release (/etc/os-release):
Role and exposure [internet-facing / internal only / behind a TCP-terminating proxy with the origin locked down]:
Accepts inbound IPv4 TCP from untrusted networks, dual-stack listeners included [yes / no]:
Running kernel (uname -r):
Installed kernel package version:
Fixed build for this platform [yes / no / vendor has no fix yet]:
net.mptcp.enabled:
MPTCP listeners (process):
Go services (Go version, multipathtcp setting):
net.ipv4.tcp_migrate_req and sk_reuseport BPF programs:
Interim measures [IP options filter / MPTCP off / GODEBUG / none], date and who:
Restarted into the fixed kernel [yes / no, time]:
Status [fixed / vulnerable / no fix yet / EOL]:
```

---

**Phase 2: Emergency patching**

**Pre-patch checklist:**

- [ ] Snapshot or back up the server or image
- [ ] Note current versions (`uname -r`, plus `dpkg -l 'linux-image*'` or `rpm -qa 'kernel*'`) for rollback
- [ ] Write down any interim measure you applied (the IP options filter, MPTCP off, a `GODEBUG` setting) so you can undo it on purpose later
- [ ] Tell stakeholders about the maintenance window. Patching ends with a restart, so plan the order: internet-facing hosts with MPTCP listeners or Go services first
- [ ] Have a rollback plan ready, with a time limit. A rollback puts the vulnerable kernel back
- [ ] For a host you suspect, capture memory and volatile state before you restart it. A kernel exploit can leave no file on disk, and a restart destroys memory evidence. DETECTION & FORENSICS says what to look for

**Patching commands:**

Install the vendor kernel that contains the fix, then restart. Restarting is not optional: the running kernel stays vulnerable until then. Patch in this order: internet-facing hosts with MPTCP listeners or Go services first, then everything else that accepts inbound IPv4 TCP.

```bash
# Debian and Ubuntu (run as root)
apt update && apt full-upgrade
# RHEL family, Fedora, Oracle Linux (run as root)
dnf upgrade 'kernel*'
# Amazon Linux 2023: repositories are versioned, so ask for the latest release (run as root)
dnf upgrade --releasever=latest 'kernel*'
# SUSE (run as root)
zypper patch
# then reboot (run as root)
systemctl reboot
```

Check whether a reboot is still pending:

```bash
# Debian and Ubuntu
cat /var/run/reboot-required
# RHEL family (needs dnf-utils or yum-utils)
needs-restarting -r
# SUSE
zypper needs-rebooting
```

These commands install a fix only where the vendor has shipped one. They cover Debian, Ubuntu, the RHEL family, Fedora, Oracle Linux, Amazon Linux 2023 and SUSE. On Azure Linux, Alpine and Arch, update the kernel package with the platform's package manager and restart. Option A and Option B say what each platform had on 4 November 2026.

**Option A: Platforms with a fixed kernel (the fix is the vendor kernel)**

- Debian: fixed in bookworm `linux` `6.1.190-1` (DLA-4841-1, 17 October), bookworm `linux-6.12` `6.12.113-1~deb12u1` (DLA-4850-1, 22 October) and trixie `6.12.113-1` (DSA-6568-1, 16 October). Forky has `7.2.12-1` and sid has `7.2.13-1`. Bullseye is covered through Freexian ELTS: `5.10.272-1` (ELA-1846-1) and `linux-6.1` `6.1.190-1~deb11u1` (ELA-1850-1). Stretch and buster are end of life.
- RHEL family: Red Hat shipped fixed kernels on 1 November (Critical): RHEL 8.10 `kernel` 4.18.0-553.182.1.el8_10 (RHSA-2026:93414), RHEL 9 5.14.0-687.64.1.el9_8 (RHSA-2026:93412) and RHEL 10 6.12.0-211.72.1.el10_2 (RHSA-2026:93413), with EUS, E4S, AUS, TUS and SAP errata after them. RHEL 6 and 7 are not affected. Rocky Linux shipped RLSA-2026:93414, 93412 and 93413 on 3 November, AlmaLinux 8 has ALSA-2026:93414 and 93415, and AlmaLinux 9 and 10 have had fixed kernels in their repositories since 2 November. No kpatch exists.
- Oracle Linux (Important): UEK was fixed on 16 October 2026. ELSA-2026-500397 covers UEK R6 5.4.17-2136.360.3.1 on OL7 and OL8, ELSA-2026-500398 covers UEK R7 5.15.0-325.221.6.4 on OL8 and OL9, and ELSA-2026-500399 covers UEK R8 6.12.0-207.111.5.4 on OL9 and OL10. Newer UEK errata (ELSA-2026-500572, -500573 and -500574) followed on 2 November, together with the Red Hat compatible kernel (RHCK) errata ELSA-2026-93414 (OL8), -93412 (OL9) and -93413 (OL10). Ksplice updates for UEK R6, R7 and R8 came on 19 October.
- SUSE (severity important): fixed `kernel-default` is at least 6.12.0-160000.40.1 for SLE 16.0 and SLE Micro 6.2, 6.4.0-150700.53.90.1 for SLES 15 SP7, 6.4.0-150600.23.143.1 for SLES 15 SP6 LTSS, 5.14.21-150500.55.195.1 for SLES 15 SP5 LTSS and Micro 5.5, and 5.14.21-150400.24.246.1 for SLES 15 SP4 LTSS and Micro 5.3 and 5.4. SLE Micro 6.0 and 6.1 are released too, and SLES 12 SP5 is in progress. Live patches are listed for SLE 12 SP5 and 15 SP4 to SP7. SLE 11 SP4 is not affected.
- Amazon Linux (Important): AL2023 `kernel6.12` is fixed in 6.12.113-138.209.amzn2023 (ALAS2023-2026-3335), `kernel6.18` in 6.18.56-125.164.amzn2023 (ALAS2023-2026-3251) and the package named `kernel` (6.1) in 6.1.189-236.400 (ALAS2023-2026-3365). On AL2 the core kernel is fixed in 4.14.355-287.758 (ALAS2-2026-4065), and so are the 5.4, 5.10 and 5.15 extras. AL2 is still marked end of support, so plan the move off it. No live patch exists for this CVE.
- Azure Linux 3.0: kernel 6.6.159.1-1.azl3 carries the fix (a Microsoft vendor fix, in the production repository since 20 October 2026). Azure Linux 4.0 is under investigation. Microsoft's update guide lists the CVE for Azure Linux with customer action required.
- Fedora 44 (kernel 7.2.15), Arch (`linux` 7.2.14, `linux-lts` 6.18.60) and Alpine (`linux-lts` 6.12.114 on 3.21 and 3.22, 6.18.59 on 3.23, 3.24 and edge) are at or above the fix (inferred). The Alpine tracker still has no package data.

**Option B: Platforms with no released fixed kernel yet (the vendor has to ship it)**

- Ubuntu: priority critical since 3 November, and no Ubuntu Security Notice yet. Canonical said on 2 November that the fixes are in the -proposed pocket for testing, prepared for 22.04 jammy (5.15.0-203.213), 24.04 noble (6.8.0-149.149), 26.04 resolute (7.0.0-43.43) and 26.10 (7.3.0-10.10). The aws, azure, gcp, gke and oracle flavours on jammy and noble are still pending. 20.04, 18.04 and 16.04 are marked "needed": affected, no fix yet. 14.04 is not affected. Ubuntu lists no Livepatch fix, and Canonical calls updates "the only appropriate mitigation".
- OpenShift 4 (RHCOS 8 and 9): still listed as affected. Red Hat's bulletin notes that its packet filter doesn't cover pod-to-pod traffic in OpenShift.
- CentOS Stream 9 and 10: the newest kernels (28 October) don't name the CVE.

While you wait for a vendor fix, in order of preference:

1. Where a workload can move, move it to a platform from Option A that already has a fixed kernel.
2. Apply the interim IP options filter on the host, or at the network edge where your edge can match IP options.
3. Close the demonstrated MPTCP path, and set `GODEBUG` for Go services.
4. Put internet-facing services behind a proxy that terminates TCP, and lock the origin to the proxy's IP ranges.
5. Check the vendor page every day, and patch the day a fixed kernel appears.

Treat every measure below as interim. Red Hat now publishes a packet filter (RHSB-2026-016) and says it reduces exposure but can't fully prevent exploitation, and Canonical says updates are the only appropriate mitigation. Vendor state moved fast between 30 October and 4 November, so re-check before you rely on a "no fix yet".

**Option C: Containers and Kubernetes nodes (patch the node)**

- Containers share the host kernel, so patch the node. Rebuilding or redeploying images changes nothing for this bug.
- Restart or replace nodes in batches that your workloads can absorb, and take each node out of rotation first. A node keeps its old kernel until it restarts or is replaced by a node image that carries the fix.
- On a managed service, the node image decides. State on 4 November:
    - GKE Container-Optimized OS: the release notes for m121, m125, m129 and m133 name the fix (m133 in cos-133-19999-44-174, 30 October), but GKE's release notes still listed 44-159 for 1.37. On 30 October m113 (6.1.161) and m117 (6.6.157) were below it (inferred). No GKE bulletin names the CVE.
    - EKS: AL2023 AMI v20261031 is fixed, per AWS bulletin 2026-160-AWS. v20261026 (27 October) had fixed only the 6.18 and 6.12 kernels.
    - Bottlerocket: v1.68.1 (2 November) uses kernel-kit 9.6.2 and carries the fix. v1.68.0 (27 October) didn't.
    - AKS: the release tracker shows node image 202610.23.0 as current. We couldn't confirm its kernels. Node image 202610.16.1 (27 October) was below the fix for both Azure Linux and Ubuntu.
    - Flatcar: stable 4757.2.2 and later, and LTS 4081.3.11 and later (inferred fixed).
    - Talos: v1.14.3 and later (inferred fixed).
    - OpenShift 4 (RHCOS 8 and 9): still listed as affected.
- kube-proxy and similar L4 forwarding pass packets, IP options included, to pods. An ingress controller that terminates TCP shields the pods behind it, but it is itself exposed. Traefik, for example, is a Go program that opens MPTCP listeners by default.
- Every pod or container network namespace starts with MPTCP enabled on upstream kernels, and a host sysctl doesn't change that. The per-namespace command is under Close the demonstrated MPTCP path below.

**Restart into the fixed kernel (the step people skip)**

Installing the package is half the job. The old kernel keeps running until the host restarts, and the host stays exposed the whole time. The restart command is in the patching commands above. Oracle Ksplice is the exception for UEK: a live patch applies the fix without a restart, so check the applied updates with Oracle's own tooling. Everywhere else, plan the restarts now, in the order above.

**Can't patch today? Narrow the exposure.** This is a bridge, not a fix. DEFENSE-IN-DEPTH MEASURES has the full list.

- Drop inbound IPv4 TCP packets that carry IP options, on the host or at the network edge where your edge can match them. Red Hat, AlmaLinux and AWS now publish rules for this. Red Hat says the filter reduces exposure but "cannot fully prevent" exploitation.
- Close the demonstrated path: turn MPTCP off, then restart the services that listen on the network.
- Put internet-facing services behind a proxy that terminates TCP, and lock origins to the proxy's IP ranges.
- Edge filtering: Cloudflare Network Firewall (Magic Firewall, for Magic Transit customers) has the fields `ip.hdr_len` and `ip.opt.type`, which can match packets with options. Cloudflare WAF rules work on HTTP and can't see IP options. Cloud security groups and network ACLs can't match IP options either.
- Setting `net.ipv4.conf.*.accept_source_route=0` does not help: the kernel checks it only for source-route options (LSRR and SSRR), not for Record Route or Timestamp.
- Write down each interim measure and the date it comes off.

**Interim filter: drop inbound IPv4 TCP packets that carry IP options (reduces exposure, not a fix)**

Use this while you wait for a fix or a restart window. A Go team member wrote on Go issue 82717 that dropping IPv4 TCP packets that carry IP options "may suffice". Red Hat now recommends the same filter in bulletin RHSB-2026-016, in preference to turning MPTCP off, and says it reduces exposure but "cannot fully prevent" exploitation. AlmaLinux and AWS publish similar rules. Red Hat and a CIQ kernel engineer both note that it misses traffic between pods or containers on the same host. Treat the filter as a way to narrow the exposure, and patch anyway.

- Cover all TCP packets, not only SYNs. Under a SYN flood the kernel switches to syncookies and reads the options again from the final ACK of the handshake (a comment in net/ipv4/syncookies.c says so).
- RFC 7126 recommends dropping Record Route and Timestamp options by default, so legitimate internet traffic with them is rare. Router Alert (used by IGMP and RSVP) is not TCP, so a rule scoped to TCP leaves it alone.
- Hosts that use CIPSO labels (NetLabel, multi-level security) carry IP options on purpose. Test before you enable the filter there.
- Don't use the nftables `ip option` expression: it only matches lsrr, ra, rr and ssrr, with no timestamp. Match the header length instead. `ip hdrlength` is the 4-bit IHL field in 32-bit words, and 5 means no options.

nftables (count first, then drop):

```bash
# run as root
nft add table ip cve_98432
nft add chain ip cve_98432 pre '{ type filter hook prerouting priority raw; policy accept; }'
nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter
# watch the counter: on normal traffic it should stay near zero
nft list table ip cve_98432
# then enforce
nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter drop
# rollback
nft delete table ip cve_98432
```

iptables alternative (u32 match; `0>>22&0x3C` is the IP header length in bytes, and 21 to 60 means options are present). It drops from its first command, so there is no counting stage. Use the nftables version where you want to count first:

```bash
# run as root
iptables -t raw -I PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP
# check hits
iptables -t raw -L PREROUTING -v -n
# rollback
iptables -t raw -D PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP
```

- These rules are not persistent. Add them to your saved ruleset after testing.
- The prerouting hook also sees traffic that the host forwards to containers. CNI plugins with eBPF datapaths can steer packets past the host's netfilter hooks, so check your CNI's documentation.

**Close the demonstrated MPTCP path**

- The kernel documentation says `net.mptcp.enabled` controls whether MPTCP sockets can be created, is per network namespace, and defaults to 1.
- The setting is checked only when a socket is created, so existing MPTCP listeners keep accepting MPTCP until their service restarts.
- Go programs fall back to plain TCP automatically.
- This closes only the demonstrated path. Plain TCP stays exposed to the underlying bug. The Go security team says the bug is not specific to MPTCP, and that systems with no MPTCP listener may be vulnerable to similar attacks.

```bash
# run as root
sysctl -w net.mptcp.enabled=0
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-cve-2026-98432.conf
sysctl --system
# then restart services that listen on the network
```

Containers: every new network namespace starts at 1. Set it inside each running container's namespace (for example `nsenter -t <container-pid> -n sysctl -w net.mptcp.enabled=0`, run as root), or through your platform's sysctl settings. New containers start at 1 again.

**Go services, per program**

- Set the environment variable `GODEBUG=multipathtcp=0` in the service definition. If GODEBUG already exists, append it with a comma. Then restart the service.
- Or rebuild with `godebug multipathtcp=0` in go.mod (Go 1.23 and later), or `//go:debug multipathtcp=0` in the main package (Go 1.21 and later).
- None of this stops code that calls `SetMultipathTCP(true)` explicitly. The Go security team calls disabling MPTCP program by program "a fragile mitigation" and says the best fix is a patched kernel. It also says it is premature to change Go's defaults, and discussion continues in Go issue 82717.

**Verification:**

```bash
# Running kernel: it must be a fixed version for your platform
uname -r

# Debian and Ubuntu: installed kernel package version
dpkg -s linux-image-$(uname -r) | grep '^Version'

# RHEL family, Fedora, Amazon Linux, Oracle, SUSE: installed kernel packages. The running one is the one uname -r names
rpm -qa 'kernel*' | sort

# Is a reboot still pending?
# Debian and Ubuntu
cat /var/run/reboot-required
# RHEL family (needs dnf-utils or yum-utils)
needs-restarting -r
# SUSE
zypper needs-rebooting

# MPTCP and migration settings: after the MPTCP change, net.mptcp.enabled shows 0
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req

# MPTCP listeners (run as root): after you turned MPTCP off and restarted the services, no listener rows should remain
ss -Mlnp

# The same inside a container's network namespace (run as root)
nsenter -t <container-pid> -n ss -Mlnp

# Interim filter: is it loaded, and is the counter moving? (run as root)
nft list table ip cve_98432
iptables -t raw -L PREROUTING -v -n
```

**Post-patch checklist:**

- [ ] Every patched host shows the fixed kernel in `uname -r`, and the pending-reboot checks come back clean
- [ ] The services work after the restart: listeners are up, health checks pass and dependent systems reconnect
- [ ] Decide on purpose what stays of the interim measures. The patch does not remove the IP options filter or the MPTCP setting. Keep them as long as you want them, or remove them with the rollback commands in the interim filter and by deleting `/etc/sysctl.d/99-cve-2026-98432.conf`
- [ ] Keep `net.ipv4.tcp_migrate_req` at 0 (the default) unless you need request migration
- [ ] If a scanner still flags a patched host, check the version-number trap before you open a ticket: a vendor kernel can carry the fix under an older upstream number
- [ ] Keep the output of `uname -r` and the pending-reboot checks as evidence
- [ ] Update your asset inventory and record the restart time
- [ ] Watch for the IPv6 follow-up. The CVE text says a separate patch will fix the same migration issue in the IPv6 request socket code. As of 30 October 2026 there is no maintainer patch and no CVE for it
- [ ] On hosts still waiting for a fix, watch the kernel log for oops and panic messages. DETECTION & FORENSICS says which ones matter

*Sources: Debian security tracker and advisories, Debian ELTS (Freexian), Ubuntu CVE tracker, Red Hat CVE page and Bugzilla, SUSE, Oracle Linux and Amazon Linux security pages, Microsoft update guide, Fedora, Arch and Alpine package versions (inferred), GKE, EKS, AKS, Bottlerocket, Flatcar and Talos release notes, Go security team announcement and Go issue 82717, Go godebug documentation, Linux kernel MPTCP and IP sysctl documentation, nftables and iptables documentation, RFC 7126, Cloudflare Network Firewall documentation (all checked on 30 October 2026), and Red Hat errata and bulletin RHSB-2026-016, Rocky Linux and AlmaLinux errata, Canonical blog, AWS bulletin 2026-160-AWS and the AKS release tracker (4 November 2026)*

#### DETECTION & FORENSICS (Day 2-3)

None of the sources we relied on lists indicators of compromise such as file hashes, address lists or request signatures. What exists is one published attack pattern, a few kernel log strings and a general method for hunting kernel-launched commands. That leaves you looking for behaviour: kernels that still carry the bug, IP options on inbound TCP, kernel crash traces, and commands that the kernel starts for an attacker. A kernel exploit can leave no file on disk, a lost race leaves no crash, and a successful exploit is designed not to crash. A clean result therefore proves nothing.

Inventory comes first, because a signal from a host whose kernel you do not know cannot be read. No exploitation has been reported (the review window under ADVANCED FORENSICS gives the dates), so most of this section is about finding exposed hosts and spotting attempts. Every command here only reads, apart from the counting rule for the options filter, which adds a firewall rule. Commands marked "run as root" need it.

**Check for signs of attempts and compromise**

**Fleet inventory at scale:**

Ask three questions of every host. Which kernel is running? Which listeners accept IPv4 TCP from networks you do not trust? Which of those listeners are MPTCP, and which belong to Go programs? Run the commands below through your configuration management, remote execution or EDR tooling, and collect the output into one table keyed by host.

```bash
# Running kernel. Compare it with the vendor's fixed version, not the upstream one
uname -r
# Installed kernel package version (Debian and Ubuntu)
dpkg -s linux-image-$(uname -r) | grep '^Version'
# Installed kernel packages (RHEL family, Fedora, Amazon Linux: kernel6.12 and kernel6.18, Oracle: kernel-uek, SUSE: kernel-default)
rpm -qa 'kernel*' | sort
# MPTCP and request migration settings
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req
# run as root. MPTCP listening sockets in the current network namespace, with processes
ss -Mlnp
# All TCP listening sockets, with processes (run as root)
ss -tlnp
# run as root. The same MPTCP check inside a container's network namespace
nsenter -t <container-pid> -n ss -Mlnp
# Go build info: Go version and compiled-in GODEBUG defaults (needs a Go toolchain; a directory is scanned recursively)
go version -m /path/to/binary
# run as root. BPF programs of the sk_reuseport kind, which could migrate requests
bpftool prog show | grep sk_reuseport
```

| What you see | Reading | Next step |
| --- | --- | --- |
| `uname -r` older than the vendor's fixed kernel | Exposed if the host accepts IPv4 TCP from untrusted networks | Patch and reboot, internet-facing hosts first |
| Fixed package installed, but `uname -r` still shows the old kernel | The fix is on disk and the host has not rebooted. It is still vulnerable | Schedule the reboot (see Kernel update cadence and live patching under DEFENSE-IN-DEPTH MEASURES) |
| A listener in the `ss -Mlnp` output | An MPTCP listener, the demonstrated path to code execution | Patch first. Turn MPTCP off as a stopgap |
| A Go binary whose module declares go 1.24 or later and shows no `multipathtcp=0` | Opens MPTCP listeners by default where the kernel allows it | Same as above, and set the Go switch (see Go build and deploy policy under DEFENSE-IN-DEPTH MEASURES) |
| Any `sk_reuseport` program in the `bpftool prog show` output | A candidate for request migration, the second path. The tool cannot show whether the program is the migrating kind | Treat every one as a candidate. Keep `net.ipv4.tcp_migrate_req` at 0 |
| Only plain TCP listeners | Still exposed to the underlying bug. Nobody has publicly shown code execution without an MPTCP listener (Go issue 82717) | Patch on the same schedule, after the MPTCP hosts |

Reading `go version -m` output:

- The "build DefaultGODEBUG=..." line appears only when it is not empty.
- A binary whose module declares go 1.24 or later, and shows no multipathtcp=0 there, opens MPTCP listeners by default. The go line is in the main module's go.mod. We read go.mod files for common servers, not their code, and a program can opt out per socket. Treat this as a first pass.

Containers share the host kernel, so the unit of inventory is the node. A scan of an image looks at files, not at the kernel the container will run on. The MPTCP setting is per network namespace, so list the container PIDs on each node with your container runtime and run the nsenter command for each one.

*Sources: kernel.org CVE record, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Oracle advisories, Linux kernel documentation, Go godebug documentation, Go security team announcement (29 October 2026), Go issue 82717*

**Network detection:**

Inbound TCP packets with IP options should be close to zero on internet links, which makes them a cheap signal. The options that matter here are Record Route and Timestamp. Two sensors cover them.

The first is the counter of the options filter. As root, set up the counting rule from the interim filter under IMMEDIATE ACTIONS (Hour 1-2). It adds a firewall rule. Leave the drop rule out for now, and read the counter:

```bash
# run as root. Read the counters of the nftables table. On normal traffic they should stay near zero
nft list table ip cve_98432
# run as root. The iptables equivalent: hit counters of the drop rule, which exist only once that rule is in place
iptables -t raw -L PREROUTING -v -n
```

The second is an IDS rule. Suricata and Snort 3 both have an `ipopts` keyword. Suricata accepts rr, eol, nop, ts, sec, esec, lsrr, ssrr, satid, qs, rtralt, cipso or any, one per rule, so write one rule per option if you want to tell Record Route from Timestamp. Both example rules below use local SIDs and match any option. The first limits the source to your external network variable and sets a class type. The second accepts any source. Check the syntax against your sensor's version before you load them.

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound TCP with IPv4 options"; ipopts:any; classtype:misc-activity; sid:1000001; rev:1;)
```

```text
alert tcp any any -> $HOME_NET any (msg:"Inbound TCP with IPv4 options"; ipopts:any; sid:1000001; rev:1;)
```

Place the sensor where it sees packets as they arrive. Behind a TCP-terminating proxy it sees the proxy's connections and not the attacker's, so a quiet sensor there says nothing about your edge.

The published attack pattern is many handshakes from one source over tens of minutes (48 minutes in the reporters' proof of concept), with Record Route or Timestamp options and retransmitted SYNs. A lost race only fails the handshake, so expect failed handshakes from the same source, not crashes. We have no published threshold for how many packets make an attack. Baseline your own traffic, then look at the shape: one source, a long period, options on the packets and SYN retransmissions.

A counter or an alert shows an attempt, not a success. Hosts that use CIPSO labels carry options on purpose, so know which of your links do. A quiet counter also proves nothing where traffic reaches the host by a path the filter does not see, such as a CNI plugin with an eBPF datapath.

*Sources: Suricata and Snort 3 documentation, nftables and iptables documentation, RFC 7126, the write-up published by the team that reported the bug (27 October 2026), kernel.org CVE record*

**Host logs, and what clean logs mean:**

| Where it shows | What it looks like | Notes |
| --- | --- | --- |
| Kernel log | `skb_under_panic: text:... len:... put:... head:... data:... tail:... end:... dev:...` | Printed before a panic. A panic is the availability impact that kernel.org, the CNA, describes |
| Kernel log | An oops that names `ip_options_build` or `ip_build_and_send_pkt` | A strong sign of attempts |
| Kernel log | `BUG: KASAN: ...` | Only kernels built with CONFIG_KASAN print it. Its absence on any other kernel means nothing |
| Reboot history | An unplanned reboot or panic on an exposed host that was not yet patched | Weak on its own. Read the kernel log of the previous boot |

```bash
# run as root: kernel messages of this boot that match the crash signs
journalctl -k -g 'ip_options_build|skb_under_panic|KASAN'
# The same through the kernel ring buffer, which only holds what has not been overwritten
dmesg | grep -E 'ip_options_build|skb_under_panic|KASAN'
# Boots the journal knows about. It lists more than one only if the journal survives reboots
journalctl --list-boots
# Kernel messages of the previous boot, for a host that panicked and came back
journalctl -k -b -1 -g 'ip_options_build|skb_under_panic|KASAN'
```

A host that keeps no persistent journal loses the ring buffer when it panics and reboots. The only copy is then whatever was forwarded off the host (see Monitoring and alerting under DEFENSE-IN-DEPTH MEASURES).

Clean logs prove nothing. A lost race leaves no crash, and a successful exploit is designed not to crash. An empty kernel log does not clear a host. A fixed kernel closes the two paths this CVE fixes, and it does not tell you what happened before it was running.

**Hunting for kernel-launched commands:**

This is general kernel-exploit hunting, not a test built for this exploit. The reporters' write-up says the payload ends by running a shell command as root from kernel context. Commands that the kernel starts through its user-mode helper normally have a kernel thread as parent, usually kthreadd (PID 2). A user-space process with that parent is unusual. Legitimate helpers (modprobe, coredump and hotplug helpers) show up too, so baseline a known-good host of the same role first.

```bash
# User-space processes whose parent is kthreadd (kernel threads show their name in brackets)
ps -eo pid,ppid,user,lstart,args | awk '$2 == 2 && $9 !~ /^\[/'
```

Four caveats apply:

- It lists live processes only. A command that ran and exited leaves nothing for `ps`. Pair it with process-creation logging from your EDR or the audit subsystem, filtered on parent PID 2.
- Only the first process in a chain has PID 2 as its parent. Its children show it as their parent, and if it exits first they are adopted by another process and no longer show PID 2.
- Run it on the host, not inside a container. Kernel threads are not visible inside a container's process namespace.
- The `$9` in the filter assumes that `lstart` prints five words. Minimal systems such as Alpine ship a `ps` that may not accept these fields. Check the output layout before you trust an empty result.

**How to read the signals together:**

| What you see | Reading | What to do |
| --- | --- | --- |
| A kernel below the fix and nothing else | Exposed, not known to be hit. Clean logs prove nothing | Patch and reboot. Copy the kernel log and the counters off the host first |
| A few TCP packets with IP options from one source | Probably a probe or an odd client. Legitimate internet traffic with Record Route or Timestamp options is rare | Note the source and the port. Check whether the host is patched |
| Many handshakes from one source over tens of minutes, with options and retransmitted SYNs | Matches the published attack pattern | Treat it as an attempt. Keep the counters and the IDS alerts, check whether the port is an MPTCP listener, and block the source if you can. The attacker can change address |
| An oops or `skb_under_panic` trace naming the options code, then a reboot | A strong sign of attempts. The reboot has already cost you the memory evidence | Keep the kernel log. Review the other signals on this host and its neighbours, and decide on a rebuild (see ADVANCED FORENSICS) |
| A user-space process whose parent is a kernel thread, and it is not in your baseline | Possible command started from kernel context | Incident. Isolate the host from the network without rebooting it, capture memory first, then follow ADVANCED FORENSICS |
| Option packets counted on a host with a fixed kernel | Odd or hostile traffic, but the fix is in | Check the source and the port. Check that other hosts of the same service are fixed |

**What root on the host could read:**

The write-up says the final command runs as root. Root reads every file and the memory of every process on the host, so the scope is the whole host and not one service. On a container node it is every container on that node. This is our reading of the write-up, not a vendor statement. Build your rotation list from what the host held:

- SSH host keys and user keys stored on the host
- TLS private keys and certificates
- Service credentials, database passwords, API tokens and signing secrets for every service on the host
- Cloud credentials that the host holds or can fetch
- Secrets mounted into containers on the node, and the node's own credentials to the cluster

**Compromise indicators checklist:**

- [ ] Every internet-facing host runs a kernel at or above the vendor's fixed version, or has a written reason and a reboot date
- [ ] No kernel log line naming `ip_options_build`, `ip_build_and_send_pkt` or `skb_under_panic` since the start of your window, or each one traced
- [ ] No unexplained panic or reboot on an exposed host
- [ ] Inbound TCP with IP options is counted at the edge or on the host, and every unexpected source is checked
- [ ] No source with many handshakes over tens of minutes that carries options
- [ ] No user-space process with a kernel thread as parent outside your baseline
- [ ] You know which listeners are MPTCP, on every host and in every container namespace
- [ ] No unexplained outbound connection from a host that should only answer inbound
- [ ] No unverified checker, proof-of-concept or live patch code was run on a production host

**If ANY indicator turns up:** start incident response. One log line is weak evidence, but a kernel-launched command, or options traffic followed by a crash on an unpatched host, is not. Keep in mind that a clean log clears nothing. If an exposed, unpatched host shows any indicator, treat it as compromised until you can show otherwise. Capture memory before you reboot (see ADVANCED FORENSICS), rebuild the host on a fixed kernel, and rotate everything it held. Do it in this order: preserve evidence, rebuild, then rotate. New secrets on an unpatched host would go to the same attacker. Rotating signing keys logs users out, so plan for that.

*Sources: kernel.org CVE record (scoring narrative), the write-up published by the team that reported the bug (27 October 2026), Linux kernel source, systemd and procps documentation*

---

#### DEFENSE-IN-DEPTH MEASURES

The fix is a patched kernel and a reboot. Red Hat says its own packet filter reduces exposure but can't fully prevent exploitation, Canonical calls updates "the only appropriate mitigation", and the Go security team calls disabling MPTCP program by program "a fragile mitigation" and says the best fix is a patched kernel. Everything in this section buys time or narrows the exposure. None of it removes the bug. The table below shows which control can filter each path to the kernel.

| Path to the kernel | Can it filter IP options? | Switch you control | Full fix |
| --- | --- | --- | --- |
| Direct connection from the internet to the host | Only a filter on the host, or at an edge you control, that reads IP headers | An nftables or iptables rule on IP options | Patched kernel and a reboot |
| TCP-terminating proxy in front (Cloudflare proxy, AWS ALB, CloudFront, any reverse proxy) | The proxy opens its own connection to the origin, so the attacker's options do not reach the origin kernel. AWS says customers behind ALB, CloudFront, API Gateway and NLB TLS listeners don't receive TCP connections from untrusted sources directly | Lock the origin to the proxy's IP ranges | Patched kernel on the origin. The proxy's own kernel is its operator's job |
| AWS Global Accelerator | Yes. AWS says it drops every incoming IPv4 packet that carries IP options | Nothing to set | Patched kernel |
| Outbound tunnel (for example Cloudflare Tunnel) | No internet-facing listener exists | Keep the origin closed to inbound traffic | Patched kernel |
| L4 passthrough load balancer (AWS NLB with TCP listeners, Google Cloud passthrough network load balancers) | Packets are forwarded, and no documentation says that options are stripped. Treat the service as exposed | Filter on the host | Patched kernel |
| Cloud virtual network, security groups, network ACLs | No AWS, Google Cloud or Azure documentation says that their networks drop or strip IPv4 options, so treat it as unknown. AWS's own interim rules filter at the instance or in AWS Network Firewall. Security groups and network ACLs cannot match IP options | None at this layer | Patched kernel |
| Cloudflare Magic Transit with Network Firewall (Magic Firewall) | Yes. The fields ip.hdr_len and ip.opt.type match packets with options | A Network Firewall rule on those fields | Patched kernel |
| Cloudflare WAF rules | No. They work on HTTP and cannot see IP options | None | Patched kernel |
| Container traffic through kube-proxy or other L4 forwarding | No. Packets, IP options included, reach the pods | A filter on the node (check your CNI) | Patched node |

**Scanner and feed coverage**

A clean scanner report still proves little. We have not tested any scanner product against this CVE, so we cannot say which ones detect it. Here is what the data feeds held on 4 November:

| Source | State on 4 November 2026 | What it means |
| --- | --- | --- |
| NVD | Status "Received", no NVD score. The page shows the CNA's 9.8 | The record is not analysed yet, so expect gaps in tools that wait for NVD |
| GitHub advisory GHSA-qp6h-4hvh-qqqc | Critical 9.8, unreviewed | A pointer, not a reviewed record |
| Distro trackers | Debian, Red Hat and its rebuilds, SUSE, Amazon Linux, Oracle and Azure Linux have fixed kernels. Ubuntu is priority critical with no notice, and its fixes are in testing | Ubuntu has no released fixed package, so no Ubuntu host can be shown as fixed yet |
| Scanners | Tenable lists 73 plugins, Rapid7 and Snyk have entries, Fortinet has an IPS signature. No nuclei template, and no Emerging Threats Open or Snort community rule | Coverage of distro kernel packages, not proof of exposure |
| CISA KEV | Not listed (catalog 2026.11.03) | A queue that ranks by KEV will not raise it |
| EPSS | 0.0076 (55.3rd percentile) on 3 November 2026 | A queue that ranks by EPSS will place it in the middle. Rank by exposure instead |
| Platforms where we inferred the status | Alpine, Fedora, Arch, Flatcar and Talos | The vendor's kernel version was compared with the upstream fixed versions, and no vendor notice names the CVE. Confirm with the vendor when a notice appears |

*Sources: NVD, GitHub Advisory Database, Debian, Ubuntu, Red Hat, Rocky Linux, AlmaLinux, SUSE, Amazon Linux, Oracle and Microsoft trackers, Tenable, Rapid7, Snyk, Fortinet PSIRT, nuclei-templates, Emerging Threats Open and Snort community rules, CISA KEV catalog 2026.11.03, FIRST EPSS API, kernel.org release pages, checked on 4 November 2026*

**The version number trap.** There are two traps here. The first is the running kernel. A host that installed the fixed package and has not rebooted still runs the old kernel, and `uname -r` still shows it. Compare the running kernel, not the installed package. The second is the number itself. Vendors backport fixes, so a fixed vendor kernel need not match any fixed upstream release. Oracle's fixed UEK R6 kernel is 5.4.17-2136.360.3.1, and upstream has no fix for 5.4 or older. SUSE's fixed kernel for SLES 15 SP5 LTSS is 5.14.21-150500.55.195.1. Take the fixed version from the vendor's advisory, and use the list of fixed upstream releases only for kernels built straight from upstream. Where we inferred a platform's status from its version number, check again when the vendor publishes a notice.

*Sources: Oracle Linux errata ELSA-2026-500397, SUSE advisories, Debian, Ubuntu, Red Hat and Amazon Linux trackers, kernel.org release pages*

---

**Server-side stopgaps (when you cannot patch today)**

None of these is complete. A patched kernel and a reboot are the only complete fix.

| Stopgap | Helps against | Leaves open | Side effects |
| --- | --- | --- | --- |
| Drop inbound IPv4 TCP packets that carry IP options (nftables or iptables) | The demonstrated path, which uses options on the attacker's packets. Red Hat recommends it, and says it reduces exposure but "cannot fully prevent" exploitation | Traffic that bypasses the host's netfilter hooks, such as CNI plugins with eBPF datapaths, traffic between pods or containers on the same host, and every host you forgot | Hosts that use CIPSO labels carry options on purpose. Test first. The rules are not persistent |
| Set `net.mptcp.enabled=0` and restart the listeners | The demonstrated MPTCP path | Plain TCP stays exposed to the underlying bug. Existing MPTCP listeners keep accepting MPTCP until their service restarts | The setting is per network namespace, and new containers start at 1 again. A service that insists on MPTCP can fail to open its socket. Go programs fall back to plain TCP |
| `GODEBUG=multipathtcp=0` for each Go program | The Go MPTCP default | Code that calls SetMultipathTCP(true), programs not written in Go, plain TCP | The Go team calls the per-program approach fragile. It needs a restart or a rebuild |
| Lock the origin to the proxy's IP ranges, behind a TCP-terminating proxy | Direct attacker packets to the origin | The proxy's own kernel, and any other listener on the origin | Needs a maintained list of ranges |
| A Network Firewall rule on IP options at Cloudflare's edge (Magic Transit customers) | Packets with options never reach your network | Anything that is not routed through Magic Transit | Needs Magic Transit |
| Keep `net.ipv4.tcp_migrate_req=0` (the default) | The sysctl route to request migration | A BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program migrates requests whatever the sysctl says | None |
| Take the service offline, or close the listener | Everything on that service | Nothing | The service is down |

*Sources: kernel.org CVE record, Red Hat CVE page, Go security team announcement (29 October 2026), Go issue 82717, Linux kernel MPTCP and IP sysctl documentation, nftables and iptables documentation, RFC 7126*

**Edge architecture**

**Option 1: put a TCP-terminating proxy in front and lock the origin.** Some services reach the internet only through a proxy that terminates TCP: the Cloudflare proxy, AWS ALB, CloudFront or any reverse proxy. The proxy opens its own connection to the origin, so the attacker's IPv4 options do not reach the origin kernel. AWS's bulletin says customers behind ALB, CloudFront, API Gateway and NLB TLS listeners don't receive TCP connections from untrusted sources directly when they follow its best practices, and that Global Accelerator drops every IPv4 packet that carries IP options. It holds only if nothing can reach the origin directly. Lock the origin firewall to the proxy's IP ranges, then test from outside your network that the origin's own address no longer answers. The proxy's own kernel is the proxy operator's problem.

**Option 2: publish through an outbound tunnel.** A service published only through an outbound tunnel (Cloudflare Tunnel, for example) has no internet-facing listener, so there is nothing for the attacker to connect to. Close the inbound ports at the origin so that the tunnel is the only way in.

**Option 3: drop packets with options at the edge.** Magic Transit customers can use Cloudflare Network Firewall (Magic Firewall), which has the fields ip.hdr_len and ip.opt.type for matching packets that carry IP options. Cloudflare WAF rules work on HTTP and cannot see IP options.

**Option 4: do not count on the cloud network or on passthrough load balancers.** No AWS, Google Cloud or Azure documentation says that their virtual networks drop or strip IPv4 options, so treat that as unknown. Security groups and network ACLs cannot match IP options. L4 passthrough load balancers (AWS NLB with TCP listeners, Google Cloud passthrough network load balancers) forward packets, and no documentation says that they strip options. Services behind them are exposed, so filter on the host. AWS's bulletin gives an instance-level iptables rule and an AWS Network Firewall rule for that.

*Sources: Cloudflare Network Firewall field reference, AWS, Google Cloud and Azure networking documentation (none says that IP options are removed)*

**IP options filtering as a standing baseline**

RFC 7126 recommends dropping Record Route and Timestamp options by default, so legitimate internet traffic that carries them is rare. Router Alert (used by IGMP and RSVP) is not TCP, so scoping the rule to TCP leaves it alone. That makes the rule cheap to keep on internet-facing hosts after this CVE, and not only as a stopgap. Red Hat recommends the rule and says it reduces exposure but "cannot fully prevent" exploitation, so treat it as a layer and not as a fix.

Four points decide whether the rule works:

- It must cover all TCP packets, not only SYNs. Under a SYN flood the kernel uses syncookies, and the kernel source (net/ipv4/syncookies.c) says that the options of the first SYN are thrown away and read again from the final ACK.
- The nftables `ip option` match only knows lsrr, ra, rr and ssrr. It has no timestamp, so do not use it. Match the header length instead: `ip hdrlength` is the 4-bit IHL field in 32-bit words, and 5 means no options.
- Hosts that use CIPSO labels (NetLabel, multi-level security) carry IP options on purpose. Test before you enable the rule.
- The prerouting hook also sees traffic that the host forwards to containers. CNI plugins with eBPF datapaths can steer packets past the host's netfilter hooks, so check your CNI's documentation.

nftables, counting first and dropping second:

```bash
# run as root
# Create a table and a prerouting chain
nft add table ip cve_98432
nft add chain ip cve_98432 pre '{ type filter hook prerouting priority raw; policy accept; }'
# Count TCP packets whose header length is not 5 words, which means they carry options
nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter
# watch the counter: on normal traffic it should stay near zero
nft list table ip cve_98432
# then enforce
nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter drop
# rollback
nft delete table ip cve_98432
```

iptables alternative. The u32 match reads the IP header length in bytes with `0>>22&0x3C`, and 21 to 60 means options are present:

```bash
# run as root
# Drop TCP packets whose IP header carries options
iptables -t raw -I PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP
# check hits
iptables -t raw -L PREROUTING -v -n
# rollback
iptables -t raw -D PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP
```

These rules are not persistent. Add them to your saved ruleset after testing, so that a reboot does not remove them, and roll them out with your configuration management to every internet-facing host and node. A host filter protects only the host that carries it. The counters live in the loaded rules and start again at zero after a reboot, so record the values first.

*Sources: RFC 7126, nftables manual, iptables extensions (u32) documentation, Linux kernel source (net/ipv4/syncookies.c), Go security team announcement (29 October 2026), Go issue 82717*

**MPTCP policy**

The kernel documentation says that net.mptcp.enabled controls whether MPTCP sockets can be created, that the setting is per network namespace, and that it defaults to 1. Upstream kernels ship with it at 1, and every new network namespace starts there. Red Hat's documentation for RHEL 8 and 9 says "By default the MPTCP support is disabled in RHEL." Many other distributions build MPTCP in: CONFIG_MPTCP=y on Ubuntu 22.04, 24.04 and 26.04, Debian bookworm and trixie, SLE 15 SP7 and 16.0, Azure Linux 3.0, Alpine linux-lts, Talos, and the Fedora and CentOS Stream common configs.

Policy: MPTCP stays off on servers unless a service needs it and someone has written down why. Turning it off closes the demonstrated path only. Plain TCP stays exposed to the underlying bug, so the setting does not replace patching or the options filter. Whether to turn it back on after patching is a decision for each service.

| Where | Setting | Notes |
| --- | --- | --- |
| Host | `sysctl -w net.mptcp.enabled=0`, plus a file in `/etc/sysctl.d` | The setting is checked only when a socket is created, so existing MPTCP listeners keep accepting MPTCP until their service restarts |
| Running container | `nsenter -t <container-pid> -n sysctl -w net.mptcp.enabled=0` (run as root) | Every new network namespace starts at 1 on upstream kernels, and a host sysctl does not change that |
| New containers and pods | Your platform's sysctl settings | New containers start at 1 again, so a one-off change on running containers is not a policy |
| Go programs | Nothing to change | They fall back to plain TCP by themselves when the kernel refuses MPTCP sockets |
| Services that ask for MPTCP (systemd sockets with SocketProtocol=mptcp, mptcpize, lighttpd) | Check each one after the change | Opt-in only. A service that insists on MPTCP can fail to open its socket |

```bash
# run as root
# Turn MPTCP off now
sysctl -w net.mptcp.enabled=0
# Keep it off after a reboot
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-cve-2026-98432.conf
# Load every sysctl file
sysctl --system
# then restart services that listen on the network
```

```bash
# run as root. Check that no MPTCP listener is left in this network namespace
ss -Mlnp
```

*Sources: Linux kernel MPTCP sysctl documentation, Red Hat MPTCP documentation (RHEL 8 and 9), Ubuntu, Debian, SUSE, Microsoft, Alpine and Talos kernel configs, mptcp.dev (secondary)*

**Go build and deploy policy**

The Go 1.24 release notes say that ListenConfig now uses MPTCP by default where supported (currently Linux only). The godebug documentation says that for Go 1.24, multipathtcp defaults to "2" (enabled by default on listeners), and that multipathtcp="0" reverts to the old behaviour. The values are 0 off, 1 listeners and dialers, 2 listeners only, 3 dialers only. The default applies when the main module's go line is 1.24 or later. A binary whose module says go 1.23 or lower keeps MPTCP off.

Third party programs are in scope too. The go.mod files of the latest releases of Caddy, Traefik, Kubernetes, etcd, Prometheus, Grafana and twelve more projects (checked on 30 October 2026) all declare go 1.24 or later with no godebug override that turns MPTCP off. They open MPTCP listeners by default wherever the kernel allows it. That is derived from go.mod, not from an audit of their code, and a program can opt out per socket.

| Where | Setting | Notes |
| --- | --- | --- |
| Service definition (systemd unit, container environment, Kubernetes manifest) | The environment variable `GODEBUG=multipathtcp=0` | If GODEBUG already exists, append the setting with a comma. Restart the service. It overrides go.mod and `//go:debug` settings |
| go.mod, Go 1.23 and later | `godebug multipathtcp=0` | Takes effect when you rebuild |
| Main package, Go 1.21 and later | `//go:debug multipathtcp=0` | Takes effect when you rebuild |
| Application code | An explicit `SetMultipathTCP(true)` | Not a switch. It overrides GODEBUG, so none of the settings above stops a program that calls it. Search your code for it |
| Kernel | `net.mptcp.enabled=0` | Go falls back to plain TCP without a rebuild. When the kernel refuses MPTCP sockets (ENOPROTOOPT), Go falls back silently |

Build policy: pin the setting in the main module of every Go service you build, so that a later rebuild keeps it. Deploy policy: set GODEBUG in the service definition of every Go service you run, third party ones included, and read the build info with `go version -m` to confirm what a binary ships with (see Fleet inventory at scale under DETECTION & FORENSICS). The Go team calls the per-program approach fragile, so treat both as a layer on top of the kernel setting and the patch. Go has not changed its defaults. The proposal to disable MPTCP by default (issue 82717) was still undecided on 4 November 2026, and the Go team calls a change premature.

*Sources: Go 1.24 release notes, Go godebug documentation, Go security team announcement (29 October 2026), Go issue 82717, go.mod files of the latest releases (30 October 2026)*

**What does NOT help:**

- `net.ipv4.conf.*.accept_source_route=0`. The kernel checks it only for source-route options (LSRR and SSRR), not for Record Route or Timestamp.
- The nftables `ip option` match. It knows lsrr, ra, rr and ssrr and has no timestamp. Use the header length field.
- A rule that drops only SYN packets. Under a SYN flood the kernel uses syncookies and reads the options again from the final ACK.
- Security groups and network ACLs. They cannot match IP options.
- Cloudflare WAF rules. They work on HTTP and cannot see IP options.
- A proxy in front of an origin that still answers direct connections.
- Turning MPTCP off as the only measure. Plain TCP stays exposed to the underlying bug, and existing MPTCP listeners keep accepting MPTCP until their service restarts.
- Setting `net.ipv4.tcp_migrate_req=0` against a BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program. It migrates requests whatever the sysctl says.
- Installing the fixed kernel package without rebooting. The running kernel stays vulnerable until the reboot.
- Counting on a quiet kernel log. Clean logs prove nothing.
- Limits inside the service: a non-root user, a read-only file system, dropped capabilities. The write-up describes a command that runs as root and starts from kernel context, so, in our reading, these limits would not contain it.
- Code from public repositories that call themselves checkers, mitigations or live patches. None of the 71 repositories that mentioned the CVE on 4 November is verified.

*Sources: Linux kernel IP sysctl documentation, nftables manual, Linux kernel source (net/ipv4/syncookies.c), Cloudflare documentation, AWS documentation, Go security team announcement (29 October 2026), the write-up published by the team that reported the bug (27 October 2026)*

---

**Container and Kubernetes hardening**

Containers share the host kernel, so patching an image does nothing for this bug. Patch and reboot the node, or replace it with a node image that carries the fixed kernel. Everything below that is a stopgap.

**Node patching:** roll the node pool, not the pods. A node that has not been replaced or rebooted since the fixed image shipped still runs the old kernel. AWS bulletin 2026-160-AWS (31 October) names the CVE, no Google Cloud or GKE bulletin does, and Microsoft's update guide lists it for Azure Linux with customer action required. This is the state of the managed node images on 4 November:

| Platform | State on 4 November 2026 |
| --- | --- |
| EKS, AL2023 AMI | Fixed in v20261031, per AWS bulletin 2026-160-AWS. v20261026 (27 October) had fixed only the 6.18 and 6.12 kernels. The ECS-optimized AMI 20261031 is fixed too |
| AKS | The release tracker shows node image 202610.23.0 as current, kernels not confirmed. 202610.16.1 (27 October) was below the fix for both Azure Linux and Ubuntu |
| GKE Container-Optimized OS | The release notes for m121, m125, m129 and m133 name the fix (m133 in cos-133-19999-44-174, 30 October), but GKE's release notes still listed 44-159 for 1.37. Below the fix on 30 October (inferred): m113 (6.1.161), m117 (6.6.157). No GKE bulletin names the CVE |
| Bottlerocket | Fixed in v1.68.1 (2 November 2026), which uses kernel-kit 9.6.2. v1.68.0 (27 October) was before the fix |
| Flatcar | Stable 4757.2.2 and later, and LTS 4081.3.11 and later (inferred fixed) |
| Talos | v1.14.3 and later (inferred fixed) |

**Per-namespace MPTCP:** every pod or container network namespace starts with net.mptcp.enabled=1 on upstream kernels, and a host sysctl does not change that. Set it inside each running container's namespace with the nsenter command under MPTCP policy above, or through your platform's sysctl settings, and put the platform setting in the pod or container template. Check a namespace like this:

```bash
# run as root. Read the setting inside a container's network namespace
nsenter -t <container-pid> -n sysctl net.mptcp.enabled
# run as root. List MPTCP listeners inside the same namespace
nsenter -t <container-pid> -n ss -Mlnp
```

**Ingress and forwarding:** kube-proxy and similar L4 forwarding pass packets, IP options included, to pods. An ingress controller that terminates TCP shields the pods behind it, but it is exposed itself. Traefik, for example, is a Go program whose go.mod declares go 1.24 or later, so it opens MPTCP listeners by default wherever the kernel allows it. Patch the nodes that run ingress controllers first. The host's prerouting hook sees forwarded traffic, and CNI plugins with eBPF datapaths can steer packets past it, so test the filter with your CNI before you rely on it.

**Contain the blast radius:**

None of this stops the bug. The command in the reporters' write-up runs as root and starts from kernel context, so a pod's own user, read-only file system, dropped capabilities and seccomp profile do not limit it. That is our reading of the reporters' write-up, not a vendor statement. What limits the damage is what shares the node:

- Keep internet-facing workloads on their own node pools, apart from workloads that hold secrets.
- Mount only the secrets each pod needs, and use short-lived credentials where you can. Rotation after an incident is then a small job.
- Limit egress with a NetworkPolicy, a security group or an egress proxy. It does not stop the bug, but it breaks a reverse shell or a tool download after code execution.
- Cordon a suspect node, and do not drain it until you have captured evidence (see ADVANCED FORENSICS).

*Sources: kernel.org CVE record, Linux kernel MPTCP documentation, release notes of EKS, AKS, Bottlerocket, Flatcar and Talos, GKE Container-Optimized OS release notes, Microsoft update guide*

---

**Kernel update cadence and live patching**

This bug shows how little notice a kernel fix gives. The fix and its technical explanation were public on the netdev list from 29 September 2026. That is 16 days before the CVE was published and 28 days before the reporters' write-up. On 30 October 2026, 15 days after the CVE was published, Ubuntu had no notice and Red Hat had no fix for RHEL 8, 9 or 10.

- Set a written cadence that gets each vendor kernel update onto every host within days of its release, with reboot windows built in. A kernel that is installed and not booted protects nothing.
- Watch the upstream stable release notes and your vendor's tracker for network fixes, not only CVE alerts. The first fixed stable releases (7.2.10 and 6.18.56) appeared on 11 October 2026, four days before the CVE was published.
- Keep an emergency path outside the normal window for a kernel bug once the reporters' write-up is public. Patch internet-facing hosts with MPTCP listeners or Go services first, then everything else that accepts inbound IPv4 TCP.
- Put end-of-life dates in the plan. kernel.org projects end of life for 5.15 and 5.10 in December 2026. No upstream fix exists for 5.4 and older, or for end-of-life non-LTS lines (for example 7.1, 7.0 and 6.19), so those users depend on a vendor backport. Debian stretch and buster are unfixed and end of life, and Amazon Linux 2 is marked end of support with its kernels pending. Move such hosts off untrusted networks, or retire them.

Check whether a reboot is still pending:

```bash
# Debian and Ubuntu: prints a notice when a reboot is pending
cat /var/run/reboot-required
# RHEL family (needs dnf-utils or yum-utils)
needs-restarting -r
# SUSE
zypper needs-rebooting
```

**Live patching.** Three vendors have one. Oracle Ksplice updates for UEK R6, R7 and R8 appeared on 19 October 2026, SUSE lists live patches for SLE 12 SP5 and 15 SP4 to SP7 (for example SUSE-SU-2026:5059-1, 3 November), and TuxCare's KernelCare covers Debian 13 at least. We found none from Ubuntu Livepatch (no Livepatch fix is listed), RHEL kpatch (Red Hat's Bugzilla entry 2553390 is still NEW and no kpatch exists) or Amazon Linux (none for this CVE). Plan on the reboot unless you run one of those three. Public repositories that mention the CVE include some that call themselves a livepatch, and none is verified. A live patch loads code into your running kernel, so do not install one that does not come from your vendor.

*Sources: Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Oracle advisories and trackers, Red Hat Bugzilla 2553390, kernel.org release pages and the netdev list archive*

---

**Monitoring and alerting**

Turn the signals on before you alert on them. A panic wipes the host's own state, so the copy that counts is the one that left the host. Write the queries in your own SIEM's syntax from the patterns in the table. Baseline first: the legitimate kernel helpers and your normal options traffic decide your thresholds.

| What to watch | Where it comes from | Alert when |
| --- | --- | --- |
| Kernel version and pending reboot | The inventory commands and the pending-reboot checks, run on a schedule | An internet-facing host runs a kernel below the vendor's fixed version, or has a reboot pending longer than your window |
| IP options counter | `nft list table ip cve_98432` (run as root), or the iptables hit counters (run as root), read on a schedule | The count rises above your baseline, or one source dominates |
| IDS alerts | The `ipopts` rule on Suricata or Snort 3 | Any alert from an external source to a listener you run, until you know your baseline |
| Kernel log lines | `ip_options_build`, `ip_build_and_send_pkt`, `skb_under_panic` and, on kernels built with CONFIG_KASAN, `BUG: KASAN`, read from a log copy held off the host | Any match |
| Panics and unplanned reboots | Your platform's host or instance status events | Any, on an internet-facing host |
| Process creation | EDR or audit events whose parent PID is 2 | A process that is not in your baseline |
| MPTCP listeners and settings | `ss -Mlnp` (run as root) and `sysctl net.mptcp.enabled`, per node and per container namespace, on a schedule | An MPTCP listener where policy says there should be none, or the setting back at 1 in a new namespace |
| Filter drift | The saved ruleset against the loaded one | The options rule is missing after a reboot |

Record the counter values and the alert state before every reboot, because both start again at zero.

---

#### ADVANCED FORENSICS

Patching means a reboot, and a reboot destroys the host's memory. A kernel exploit can leave no file on disk, so volatile state may be the only evidence. On any host that showed one of the signals above, capture first and patch second. Work in order of how fast things disappear: memory first, then processes and connections, then container and node state, then logs, then the disk.

**Capture memory and volatile state before any reboot:**

Take a memory image with a Linux memory acquisition tool such as LiME or AVML, and follow the tool's own documentation. This document gives no capture commands. Bring a trusted copy of the tool to the host, write the image to an evidence volume or a remote destination and not to the application disk, and hash it as soon as it exists. Some tools need a module built for the exact running kernel, so prepare them before an incident, not during one. A tool that runs inside a suspect kernel has to trust that kernel. Where your platform offers it, a hypervisor snapshot that includes memory is harder for an attacker to interfere with.

A memory image holds every secret the host had, so encrypt it and limit who can read it. Reading one takes specialist tools and symbols that match the exact kernel build. Capture it, hash it and hand the analysis to someone who does this for a living. Keep the output of `uname -r` and the kernel package version with it.

Then capture the volatile state around it:

```bash
# run as root. Send each output to a file on the evidence volume, not the application disk
# Kernel release and build
uname -a
# Every process with its parent, owner and start time
ps -eo pid,ppid,user,lstart,args
# All TCP sockets with their processes
ss -tanp
# MPTCP listeners with their processes
ss -Mlnp
# Addresses and routes
ip addr
ip route
# Loaded kernel modules
cat /proc/modules
# Firewall rules and counters as loaded now
nft list ruleset
iptables -t raw -L PREROUTING -v -n
# BPF programs
bpftool prog show
# Kernel messages of this boot and, if the journal keeps it, of the previous boot
journalctl -k --no-pager
journalctl -k -b -1 --no-pager
```

Capture the connections first, then isolate the host: cut its network at the switch, the security group or the hypervisor, and do not shut it down. For a Kubernetes node, cordon it so that no new pods land there, and do not drain it. Draining evicts the pods and takes their evidence with them.

**Kernel-thread parent hunting:**

Run the kthreadd hunt from DETECTION & FORENSICS before anything changes the process list, and run it on the host itself, not in a container. Record each result in full: the process, its parent and children, its start time, and its sockets from the list you captured above.

```bash
# User-space processes whose parent is kthreadd (kernel threads show their name in brackets)
ps -eo pid,ppid,user,lstart,args | awk '$2 == 2 && $9 !~ /^\[/'
# run as root. The process tree, to see what each hit started
ps -eo pid,ppid,user,lstart,args --forest
# run as root. One process in detail: owner, parent and state
cat /proc/<pid>/status
```

A hit that is a shell, a download tool or an unknown binary, and is not in your baseline, is an incident. A hit that matches a legitimate helper (modprobe, a coredump handler or a hotplug helper) is not. If the start time lines up with options traffic from one source, that is the sequence to chase. A clean result does not clear the host: the command lists live processes only, and anything that has already exited leaves nothing.

**Why a kernel-level compromise means rebuilding the host:**

The reporters' write-up says the exploit ends with a shell command that runs as root and starts from kernel context. Once an attacker has run code in the kernel or as root, the host can no longer vouch for itself. The process list, the file listing, the module list and the logs all come from a system that the attacker may control, so a scan that finds nothing proves nothing. A patched kernel stops new attempts, and it removes nothing that the attacker already installed. This is our reasoning, not a vendor statement, and it is standard practice after any root-level compromise.

If a host shows a kernel-launched command, or you cannot rule one out, rebuild it:

- Preserve first: memory, volatile state, logs, and a disk image or snapshot.
- Rebuild from a known-good image that carries a fixed kernel, not from a copy of the old system disk.
- Restore data only after you have checked it. Do not restore binaries, scripts, cron entries, unit files or configuration from the old host without reading them.
- Rotate everything the host could read or reach (see What root on the host could read under DETECTION & FORENSICS). Rotate after the rebuild, not before: new secrets on an unpatched host would go to the same attacker. Rotating signing keys logs users out, so plan for that.
- Treat every pod that ran on a compromised node as exposed, together with the secrets mounted into it and the node's own credentials.
- Check the neighbours: every host that the machine could reach with the credentials it held.

Patching in place is acceptable for a host with no indicator and no link to an attempt.

**Evidence handling:**

- Record who collected what, when, from which host, and with which tool and version. Record the host's clock offset from UTC, and keep every timestamp in UTC.
- Hash each item with SHA-256 right after you collect it, write the hashes to a separate file, and keep a read-only copy off the host.
- Work on copies. Keep the originals untouched.
- Encrypt memory images, logs and exports, at rest and in transit, and limit who can read them.
- Log every command you run on the suspect host, and note whether it only read or changed something.
- If you expect legal action or an insurance claim, image the disk (a volume snapshot on a cloud host) before you rebuild the host.

**Building the timeline:**

Put every source on a single UTC timeline and mark each entry: exposure (a vulnerable kernel was running), attempt (options traffic, a crash trace), or possible success (a command with a kernel parent).

| Source | What it gives you |
| --- | --- |
| Boot history and package history | When each host last booted a vulnerable kernel, and when it installed and booted the fix |
| Counters, IDS alerts, flow and packet records | Options traffic by source, port and time. Counter values help only if you recorded them with a time |
| Kernel logs of this boot and earlier ones | Oops and panic traces that name the options code, panics, reboots |
| Process start times | The `lstart` column of the process list, for every hit of the kernel-thread hunt |
| Platform logs | Cloud audit logs, instance status events and orchestrator events for the node |
| Credential use | Where the secrets from the host were used afterwards, and from which addresses |

In the reporters' proof of concept, the first stage took 48 minutes and the second took 5. Real timing will differ. The sequence to look for is a long, repeated series of handshakes from one source, followed by a command with a kernel parent.

**The window to review:**

No exploitation has been reported. On 4 November Rapid7 lists exploited_in_wild as false, Wiz and Feedly show no evidence, Previdian says "No Exploitation Yet", AWS has "no evidence" of use, Fortinet lists it as not known exploited, and CISA's Known Exploited Vulnerabilities catalog does not list the CVE. The reporters' write-up describes a working exploit, but no exploit code was published and no release was announced. The CERT advisories that now name the CVE (NCSC-NL, CCCS, CERT-FR, HKCERT) report no attacks. No public exposure counts exist.

| Window | Starts | Use it when |
| --- | --- | --- |
| Minimum | 27 October 2026 | Always. The reporters' write-up, which describes remote command execution as root, appeared that day and was updated on 28 October 2026 |
| Margin | 15 October 2026, 12:08 UTC | Your logs reach that far. The CVE record was published then, and fixed releases for every maintained upstream line were out by the end of that day |
| Maximum | 29 September 2026, 21:43 UTC | The host is internet-facing, runs an MPTCP listener or Go services, holds sensitive data, and you keep logs that long. The fix and its explanation became public on the netdev list at that time, so it is the earliest date anyone could have worked from the public text |

The window ends when each host booted a fixed kernel, not on the day you installed the package.

*Sources: kernel.org CVE record and release notes, netdev list archive (29 September 2026), the write-up published by the team that reported the bug (27 October 2026), CISA KEV catalog 2026.11.03, Rapid7, Wiz, Feedly and Previdian pages, AWS bulletin 2026-160-AWS, Fortinet PSIRT, NCSC-NL, CCCS, CERT-FR and HKCERT advisories, GitHub repository search (4 November 2026)*

**Public repositories named after the CVE:** 71 GitHub repositories mentioned the CVE on 4 November, up from 11 on 30 October. None is verified. Their descriptions include checkers, mitigations, audits, a livepatch, a trigger that says it does no code execution, and a "lab root-shell kit" that says it is not a stock remote exploit. Running unknown proof-of-concept code is a common way to get compromised, so do not test your hosts with it. If anyone on your team ran one against a real host or a laptop, treat that machine as suspect. We have no hashes, addresses or request signatures for this CVE, so there is nothing to put on a blocklist.

**When to bring in outside help:**

- A user-space process has a kernel thread as parent, and you cannot explain it from your baseline
- An oops or panic that names the options code hit an exposed host, and you cannot show that it was patched at the time
- Secrets from a suspect host were used from addresses you do not recognise
- You hold a memory image and nobody on the team can read it
- A host was already rebooted or rebuilt and its logs rotated, and the service handled customer or regulated data. The question then changes from "was it exploited" to "what could root on that host see", and the notification duties in COMPLIANCE & LEGAL REQUIREMENTS apply

Do not wipe or rebuild a suspect host before you have preserved it.

---

## BUSINESS IMPACT ANALYSIS

### Financial impact scenarios

The scenarios stay qualitative. No source for this bug gives cost figures, so none are given here.

#### Scenario 1: Prevention (patch this week)

**Costs:**

- Staff time: finding every Linux host, node and appliance that accepts inbound IPv4 TCP, then a kernel update, a reboot and checks for each
- Testing: a regression pass per critical service. A new kernel is a bigger change than a library update, so confirm that each host boots it and that networking, storage and services come back
- Reboots: the running kernel stays vulnerable until the host restarts. Where no fix has shipped yet (Ubuntu on 4 November), the cost is a stopgap now and a second change window when the fix lands
- End-of-life upgrades: a move to a supported distribution or kernel for every host on a line with no upstream fix (5.4 and older) and no vendor backport
- Downtime: none if you reboot one node at a time behind a load balancer, a maintenance window for a single host

**Benefits:**

- No breach costs, no notifications, no letters from regulators
- An accurate Linux inventory, covering cloud images, Kubernetes nodes and appliances, plus a list of which hosts accept inbound IPv4 TCP directly and which sit behind a proxy that terminates TCP. You'll want both for the next kernel advisory
- A map of which services open MPTCP listeners, including Go programs that do so by default

*Sources: kernel.org ChangeLog files, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle Linux and Microsoft advisories, Go security team announcement*

---

#### Scenario 2: Breach through an exposed internet-facing server

**How it plays out:** an attacker with no credentials sends crafted connection requests to an MPTCP listener, wins a timing race in the kernel and runs a shell command as root. With root, the attacker reads the secrets the host holds and moves on to the databases, cloud accounts and internal services those secrets open. Then data theft or extortion. The reporters' write-up (27 October 2026) describes this against servers with an MPTCP listener, with a proof of concept that took 48 minutes to leak a kernel pointer and 5 more minutes to reach command execution. A lost race only fails the handshake, so the attacker can retry. This is a plausible chain, not an observed one: no exploitation in the wild had been reported by 4 November 2026.

**Costs:**

- Forensics and incident response, legal counsel, breach notification
- Downtime while you rebuild every affected host from a clean image and rotate its secrets. Once an attacker has root, the host's own logs and tools prove nothing
- Regulatory exposure if personal data was involved
- Higher cyber insurance premiums at renewal

*Sources: the reporters' write-up of 27 October 2026, Go security team announcement of 29 October 2026, CVE record (CNA: kernel.org)*

---

#### Scenario 3: Quiet probing with no crash and no log entry

**What's different:** the CVE record says stale options are copied into the SYN-ACK sent back to the peer, which can disclose kernel heap memory. The reporters' write-up uses that leak as its first stage, to defeat kernel address randomisation (KASLR) from the network, before a second stage runs a command. A lost race leaves no crash, and a successful run is designed not to crash. You may not know anything happened until stolen credentials or unexpected access turn up somewhere else.

**Costs:**

- Rotating every secret a suspect host held (database and cache credentials, API keys, signing and session secrets, SSH keys, TLS private keys, cloud and third party tokens) and forcing users to log in again
- Investigating every system those secrets open (databases, payment APIs, cloud accounts, email)
- Notification if personal data was on the host at the time. One host serves many users and services, so that can include other people's tokens and request bodies
- Evidence against speed: a kernel exploit can leave no file on disk, and a reboot destroys memory evidence. On a host you suspect, you capture memory and volatile state first and patch second, which delays the fix
- Time: leaked credentials can sit unused for a long time

*Sources: CVE record (CNA: kernel.org), the reporters' write-up of 27 October 2026*

---

#### Scenario 4: Appliances and embedded devices waiting on a vendor

**What's different:** you can't patch these yourself. Any appliance or embedded device that runs a Linux kernel from 4.4 onward and has a listening TCP port reachable over IPv4 (a management page, a VPN portal, a file share) is in scope, and the fix has to come as a vendor update. Upstream has no fix for 5.4 and older, so those vendors must backport one. Some distribution vendors have done that on old lines: Oracle for UEK R6 on 5.4.17, SUSE for 5.14 and 6.4 based kernels. This analysis covers no appliance vendor's notice, so the wait has no known end date. Upstream did fix 5.10 and 5.15 (5.10.272 and 5.15.223), but kernel.org projects both lines to end of life in December 2026, so check how long your vendor will keep backporting.

**Costs:**

- Exposure for as long as the vendor takes, with the fix out of your hands
- Compensating controls in the meantime: take management and service ports off untrusted networks, put the device behind a firewall or a TCP-terminating proxy, and drop inbound IPv4 TCP packets that carry IP options in front of it where your firewall can match them (Red Hat says this reduces exposure but can't fully prevent an attack)
- Chasing the vendor for a written answer on whether the device is affected and when a fix ships
- Replacement or isolation if the vendor won't ship a fix. A device on a line that nobody patches stays vulnerable

*Sources: kernel.org stable and longterm release pages, Oracle Linux and SUSE advisories, Go issue 82717*

---

### Operational impact timeline

**Hour 0-24: Inventory and patching**

- Platform and ops teams pulled off roadmap work
- A list of every Linux host, VM, container node and appliance that accepts inbound IPv4 TCP: running kernel version, listening ports, MPTCP setting, and whether a proxy that terminates TCP sits in front
- Fixed kernels installed and hosts rebooted, internet-facing hosts with MPTCP listeners or Go services first, then everything else that accepts inbound IPv4 TCP
- Stopgaps for hosts that must wait for a reboot window or a vendor fix: the IP options filter and the MPTCP switch
- Decisions on appliances, on kernels with no upstream fix, and on distributions that have no fix yet

**Day 2-7: Verification**

- Confirm the running kernel (not the installed package) on every host after the reboot
- Network and host log review over the window set out under ADVANCED FORENSICS, and further back where your retention allows
- Chasing vendors, cloud providers and appliance suppliers for written answers, and for the fixes still pending on 4 November (Ubuntu, OpenShift 4)
- Removing stopgaps that broke features, once patches are confirmed (the options filter, for example, on networks that use CIPSO labels on purpose)

**Week 2-4: Hardening**

- Upgrade projects for hosts on end-of-life distributions and kernels, onto a line with enough support left (kernel.org projects end of life for 5.15 and 5.10 in December 2026)
- Origin lock-down behind a TCP-terminating proxy, and firewall limits for admin ports
- New detection rules (inbound TCP with IP options, kernel crash signs) and longer log retention
- Routine rolling reboots and node image rebuilds

**Month 2-6: Only if you found a compromise**

- Regulator questions, customer communications, possible claims
- Audit follow-ups and insurer reviews

*Sources: kernel.org release pages, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Oracle Linux advisories, Go security team announcement*

---

### Cost-benefit analysis

| Option | Effort | What's left exposed | Verdict |
| --- | --- | --- | --- |
| Patch and reboot now | A kernel package update and a reboot per host (one node at a time behind a load balancer) | Nothing known for this CVE once the host runs the fixed kernel. The IPv6 CALIPSO follow-up has no maintainer patch yet | Do this |
| IP options filter plus the MPTCP switch, patch later | A few firewall commands and a sysctl per host, and a restart of each listening service for the MPTCP switch | Whatever the filter doesn't cover, such as traffic between pods or containers on the same host. Red Hat recommends the filter but says it can't fully prevent exploitation. The MPTCP switch closes only the demonstrated path | A bridge for days, not weeks |
| Put exposed services behind a TCP-terminating proxy | An architecture change per service, plus an origin firewall locked to the proxy's IP ranges | The proxy's own kernel, which is its operator's problem, and anything still reachable directly. L4 passthrough load balancers forward packets, so they don't count. AWS says customers behind its TCP-terminating services don't receive untrusted TCP connections directly | A good layer, not a fix |
| Live patch | Oracle Ksplice (UEK R6, R7 and R8, 19 October 2026), SUSE live patching (SLE 12 SP5 and 15 SP4 to SP7) and TuxCare KernelCare (Debian 13 at least). None found for Ubuntu Livepatch, RHEL kpatch or Amazon Linux | Nothing known for this CVE once the update is applied | Use it where your vendor has one |
| Move off an end-of-life distribution or kernel | A migration project | Nothing once moved. Until then everything, because no upstream fix exists for 5.4 and older | Required. Internet-facing hosts first |
| Appliance or embedded device waiting on its vendor | A written query to the vendor, plus firewall rules and network placement | Everything until the vendor ships a fix | Compensating controls now, the vendor's fix when it ships |
| Wait | None today | Everything | Not acceptable on an internet-facing host. The fix and its explanation have been public since 29 September 2026, the reporters describe remote root command execution, and fixed kernels exist upstream and in several distributions |

*Sources: Go security team announcement, Go issue 82717, Red Hat CVE page, Oracle Linux advisories, kernel.org ChangeLog files, the reporters' write-up of 27 October 2026*

---

## COMPLIANCE & LEGAL REQUIREMENTS

### Regulatory notification obligations

If you find signs of compromise, these timelines may start running. A clean upgrade triggers none of them, and a kernel crash on its own is not a personal data breach. Whether personal data was reached is a legal judgment that depends on what the host could read, and an attacker with root can read everything the host holds. This is a summary, not legal advice.

#### GDPR (EU) and UK GDPR

- **Timeline:** 72 hours to notify the supervisory authority after becoming aware of a personal data breach, unless it's unlikely to put people at risk
- **Individuals:** without undue delay if the risk to them is high
- **Fines:** up to EUR 20 million or 4% of worldwide annual turnover (UK: GBP 17.5 million or 4%)
- *Source: GDPR Articles 33, 34 and 83*

#### NIS2 (EU essential and important entities)

- **Early warning:** within 24 hours of becoming aware of a significant incident
- **Incident notification:** within 72 hours
- **Final report:** within one month
- *Source: Directive (EU) 2022/2555, Article 23*

#### India: CERT-In and DPDP

- **CERT-In:** report covered cyber incidents, including unauthorised access and compromise of systems, within 6 hours of noticing them
- **DPDP Act 2023:** breach-reporting duties phase in under the DPDP Rules 2025, so check whether they apply to you yet
- *Source: CERT-In Directions under Section 70B(6) of the IT Act, 28 April 2022*

#### SEC (US-listed companies)

- **Timeline:** Form 8-K Item 1.05 within four business days of determining that a cybersecurity incident is material
- *Source: SEC cybersecurity disclosure rules (2023)*

#### HIPAA (US healthcare data)

- **Timeline:** notify affected individuals without unreasonable delay, and no later than 60 days after discovery. HHS too, and the media if more than 500 residents of a state or jurisdiction are affected
- *Source: 45 CFR 164.400-414*

#### US state breach laws

- All 50 states have breach notification laws. Timelines and triggers vary by state

---

### Documentation requirements checklist

**Create and maintain:**

- [ ] **Incident timeline** with precise timestamps
    - When the issue became public (fix on the netdev mailing list 29 September 2026, CVE record 15 October 2026, reporters' write-up 27 October 2026)
    - When your organization learned about it
    - When inventory, patching, reboots and verification finished
- [ ] **Technical details:**
    - Inventory of Linux hosts and appliances, with distribution, running kernel version, listening services, MPTCP setting and exposure path
    - Kernel versions before and after patching, with reboot times
    - Any evidence of compromise
    - Stopgaps applied and removed (firewall rules, sysctl settings, GODEBUG settings)
- [ ] **Business impact assessment:**
    - Systems and data at risk
    - Customer impact
- [ ] **Decision log:**
    - Who authorized what, and why
    - Risk decisions on end-of-life kernels, on appliances that waited for a vendor, and on distributions that had no fix yet
    - The reasoning behind any "no compromise" conclusion. A lost race leaves no crash and a successful exploit is designed not to crash, so "we found nothing" is weaker evidence here than it would be for a bug that drops files
- [ ] **Communications log:**
    - Who was told what, and when

**Retention:** follow your industry's record-keeping rules. Seven years is a common default.

---

### Insurance considerations

- [ ] Check that your cyber policy is active and what it covers (investigation, business interruption, liability, notification costs)
- [ ] Check the notification deadline in the policy. Many require notice within 24 to 72 hours of a suspected incident
- [ ] Check whether you must use the insurer's panel of response firms
- [ ] Keep evidence of your patching speed: dates, kernel versions and reboot times. Insurers look hard at known, unpatched vulnerabilities

**Call your broker straight away if:**

- You find indicators of compromise
- You're taking systems offline or running on stopgaps for more than a few days
- You're unsure what your policy covers

---

## DECISION MATRIX

### What should we do right now?

| Your situation | Immediate action | Priority | Timeline |
| --- | --- | --- | --- |
| Running kernel at or above the fixed version for its line (7.2.10, 6.18.56, 6.12.113, 6.6.159, 6.1.190, 5.15.223, 5.10.272, 7.3), or a vendor kernel that its advisory lists as fixed, and the host has rebooted | Document it, keep monitoring | LOW | This week |
| Fixed kernel installed, host not rebooted | Reboot now (rolling, one node at a time) | HIGH | Today |
| Unpatched, listeners reachable only from trusted networks | Patch and reboot | HIGH | 48 hours |
| Unpatched, internet facing, accepts inbound IPv4 TCP directly (above all with MPTCP listeners or Go services) | Patch and reboot, or apply the IP options filter and the MPTCP switch until you can | CRITICAL | Today |
| Unpatched, internet facing only through a TCP-terminating proxy, origin locked to the proxy's IP ranges | Patch and reboot in the normal window, and confirm the origin lock (AWS says customers behind its TCP-terminating services don't receive untrusted TCP connections directly) | HIGH | 48 hours |
| Platform with no released fix yet (on 4 November: Ubuntu, OpenShift 4, CentOS Stream, and AKS until its node image kernel is confirmed) | Apply the stopgaps, watch the vendor, patch the day the fix ships | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Kernel line with no upstream fix (5.4 and older, or an end-of-life line such as 7.1, 7.0 or 6.19) and no vendor backport | Ask the vendor for a backport, or move to a supported kernel. Stopgaps and isolation meanwhile | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Appliance or embedded device on Linux 4.4 or later, waiting on its vendor | Take its listeners off untrusted networks, filter in front of it, ask the vendor in writing | CRITICAL if its listener is internet facing, otherwise HIGH | Today, or 48 hours |
| Go service (go 1.24 or later) on a host you can't patch yet | Turn MPTCP off for the host or the program (fragile), filter IP options, patch the kernel | CRITICAL if internet facing, otherwise HIGH | Today, or 48 hours |
| Don't know which hosts accept inbound IPv4 TCP | Run the inventory commands | CRITICAL | 2 hours |
| Kernel panic with skb_under_panic, an oops naming ip_options_build, or unexpected commands started by the kernel on an exposed host | Start incident response. Capture memory and volatile state before any reboot | EMERGENCY | Immediately |
| Not affected (RHEL 6 or 7, kernel older than 4.4), or affected with no TCP listener reachable over IPv4 | Document it, patch in the normal update cycle | LOW | This week |

*Sources: kernel.org ChangeLog files, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux, Oracle Linux and Microsoft advisories, Go security team announcement, the reporters' write-up of 27 October 2026*

---

### Risk decision framework

**For each Linux host, node, appliance and container platform:**

```
Step 1: Exposure path (any one is enough)
- MPTCP listener reachable over IPv4 from the internet (the
  demonstrated path), including Go services whose go.mod says
  go 1.24 or later, on a kernel
  that allows MPTCP                                                  HIGH
- Plain TCP listener reachable over IPv4 from the internet            HIGH
- Dual-stack IPv6 listener (:: without IPV6_V6ONLY), which takes
  IPv4 connections too                                               HIGH
- L4 passthrough load balancer, kube-proxy or similar forwarding
  packets (IP options included) to the host or pod                   HIGH
- Listener reached only from trusted internal networks              MEDIUM
- Reached only through a TCP-terminating proxy, origin locked to
  the proxy's IP ranges                                              LOWER
- No TCP listener reachable over IPv4                                LOWER

Step 2: Kernel
- Running kernel below the fixed version for its line                HIGH, patchable today
- Fixed kernel installed, host not rebooted                          HIGH, reboot today
- Vendor fix not released yet (Ubuntu on 4 November)                 HIGH until it ships
- No upstream fix (5.4 and older, end-of-life lines), no backport    HIGH, wait on the vendor
- Fixed kernel running                                               LOWER

Step 3: Data and blast radius
- Personal, payment or health data, or secrets for other systems     HIGH
- Public content only, no secrets, restricted network paths          LOWER

Step 4: Action
Internet facing + any other HIGH       Patch and reboot today (filter until then)
Internal + any other HIGH              Patch within 48 hours
Everything else                        Patch this week
```

Two other situations count as exposure when you have them: request migration (`net.ipv4.tcp_migrate_req=1` or a BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program) opens a second path to the same bug, and a dual-stack IPv6 listener hands IPv4 connections to the IPv4 code.

*Sources: kernel.org CVE record, kernel source (net/ipv4 and net/ipv6/tcp_ipv6.c), kernel MPTCP and IP sysctl documentation, Go security team announcement, Go 1.24 release notes*

---

### Go/no-go decision checklist

**Before you approve emergency patching:**

- [ ] Backup or snapshot taken (cloud hosts: an image of the current state, and the previous kernel left installed so the host can boot back into it)
- [ ] Rollback plan written down. A rollback puts the vulnerable kernel back, so give it a time limit and keep the stopgaps on
- [ ] Stakeholders told about the maintenance window and the reboot
- [ ] Short test plan agreed (host boots, networking and storage come up, services start, logins, health checks, backups, monitoring agents)
- [ ] Someone on call during and after the change
- [ ] Reboot method confirmed (rolling reboot behind the load balancer, drain and replace for Kubernetes nodes, new image for autoscaling groups)
- [ ] Right fix confirmed for each platform: the vendor kernel package that the vendor's advisory names, or the stopgaps where the vendor has no fix yet
- [ ] Hosts you suspect: memory and volatile state captured before the reboot

**If you can't tick every box:**

- Take the exposed service offline for now (safest)
- Apply the stopgaps (see IMMEDIATE ACTIONS) and keep them on
- Restrict access to trusted networks until you can patch

---

## FREQUENTLY ASKED QUESTIONS

### For executives

**Q: How do we know if we're affected?**

**A:** Ask IT three questions. Which Linux hosts, nodes and appliances do we run, and which kernel is each running right now (the running kernel, not only the installed package)? Which of them accept inbound IPv4 TCP connections from outside, directly and not through a proxy that terminates the connection? Do any of them run services with MPTCP listeners, Go programs included? A kernel from 4.4 up to the fixed versions, with a port that outsiders can reach over IPv4, needs attention. Only machines that accept incoming connections matter, because outgoing connections do not use the affected code. Kernels older than 4.4 and RHEL 6 and 7 are not affected. Hosts with no listening port that untrusted IPv4 networks can reach, and IPv6-only services, are less exposed. If a hosting company or platform runs your servers, ask in writing. The inventory commands are under AM I AFFECTED? SELF-ASSESSMENT.

*Sources: CVE record (CNA: kernel.org), kernel.org stable ChangeLog files, Red Hat CVE page, Debian, Ubuntu, SUSE and Oracle Linux advisories*

---

**Q: What's the worst that could happen?**

**A:** Someone on the internet, with no login and no help from a user, sends crafted connection requests to a server, wins a timing race inside the kernel and runs commands as root. From there they can read whatever the machine can read: database passwords, API keys, customer data. The CVE record lists disclosure of kernel memory, out-of-bounds kernel writes with possible control-flow corruption, and a kernel panic or oops. The reporters say a failed attempt only fails the handshake, so an attacker can try again and again. The demonstrated attack needs a server with an MPTCP listener. Nobody has publicly shown code execution without one, and the Go security team says hosts without an MPTCP listener may be open to similar attacks.

*Sources: CVE record (CNA: kernel.org), the reporters' write-up of 27 October 2026, Go security team announcement*

---

**Q: Is anyone exploiting this?**

**A:** Not that anyone has reported. On 4 November Rapid7 lists exploited_in_wild as false, Wiz and Feedly show no evidence, Previdian says "No Exploitation Yet", AWS has "no evidence" of use, Fortinet lists it as not known exploited, CISA hasn't added the CVE to its exploited list (catalog 2026.11.03), and the EPSS score is 0.0076 (55.3rd percentile, 3 November). The reporters' claims are a different matter. The reporters' write-up of 27 October 2026 describes remote root command execution against servers with an MPTCP listener. Their proof of concept took 48 minutes to leak a kernel pointer and 5 more to run a command. It names no tested kernel versions or distributions, and no exploit code had been published by 3 November. 71 GitHub repositories mentioned the CVE on 4 November, and none is verified. That picture can change quickly, so check again before you rely on it. The sources are set out under ATTACK TIMELINE.

*Sources: the reporters' write-up of 27 October 2026, Rapid7, Wiz, Feedly, Previdian, AWS bulletin 2026-160-AWS, Fortinet PSIRT, CISA KEV catalog, FIRST EPSS API, The Hacker News (3 November 2026), GitHub repository search for the CVE ID*

---

**Q: The ratings disagree, Critical 9.8 or Important 8.1. Which is it?**

**A:** Both are on the record, and each comes from a different scorer. The kernel.org CNA scores CVSS 3.1 9.8 (Critical), and Red Hat moved to the same 9.8 by 4 November, after 8.1 on 30 October. SUSE, Amazon Linux and Oracle Linux still rate it Important at 8.1. Ubuntu raised its priority to critical on 3 November, and Debian has assigned no urgency. NVD shows no score of its own (status "Received"). Our position: treat it as critical for internet-facing Linux servers that accept inbound IPv4 TCP connections directly, above all those with MPTCP listeners, and as high everywhere else. Patch first, argue about the label later. RISK DASHBOARD lists every rating, and the technical questions below explain the gap.

*Sources: kernel.org CVE record, Red Hat, SUSE, Amazon Linux and Oracle Linux pages, Ubuntu and Debian trackers, NVD*

---

**Q: Why did we hear about this so late?**

**A:** The fix and its technical explanation were public on the kernel networking mailing list from 29 September 2026, and the commit message explains the use-after-free. The CVE was published 16 days later, on 15 October, and the reporters' write-up came 28 days after the fix, on 27 October. Vendor notices came in between: Debian and Oracle on 16 October, Amazon Linux and SUSE on 24 October, Red Hat on 1 November, and Ubuntu's fix was still in testing on 4 November. A tool that waits for a CVE record had nothing before 15 October, and one that waits for a vendor advisory had nothing before 16 October. Tools can still find old kernels, flag hosts with exposed listeners, count inbound TCP packets with IP options and catch what an attacker does after getting in. The upgrade and the reboot are the only real fix. The technical questions below cover why a scanner may stay silent.

*Sources: netdev mailing list posting of the fix, CVE record, Debian, Oracle Linux, Amazon Linux and SUSE advisories, Ubuntu and Red Hat trackers*

---

**Q: We run on a cloud provider or managed Kubernetes. Do we need to do anything?**

**A:** Get a written answer from your provider, and ask which kernel your nodes run right now. A new node image helps only once your nodes run it. AWS bulletin 2026-160-AWS (31 October) says the EKS AL2023 AMI v20261031 and the ECS-optimized AMI 20261031 are fixed, and Bottlerocket v1.68.1 (2 November) carries the fix. AKS rolled out node image 202610.23.0, but we couldn't confirm its kernels, and the earlier 202610.16.1 was below the fix. On GKE, the Container-Optimized OS release notes for m121, m125, m129 and m133 name the fix, and no Google Cloud or GKE bulletin names the CVE. Azure Linux 3.0 has the fix in kernel 6.6.159.1-1.azl3, and Microsoft's update guide lists the CVE for Azure Linux with customer action required. The status per platform is under RISK DASHBOARD.

*Sources: AWS bulletin 2026-160-AWS, Microsoft update guide, EKS AMI release notes, AKS release notes and release tracker, Container-Optimized OS and GKE release notes, Bottlerocket release notes, GKE security bulletins (4 November 2026)*

---

**Q: We're on an end-of-life kernel, an old distribution or an appliance. What now?**

**A:** Upstream has no fix for 5.4 and older, or for end-of-life non-LTS lines such as 7.1, 7.0 and 6.19, so your vendor's backport is the only route. Some vendors have shipped one: Oracle fixed UEK R6 (5.4.17), SUSE fixed SLES 15 SP4 and SP5 LTSS (5.14 based) and SP6 LTSS (6.4 based), and Debian bullseye is fixed through Freexian ELTS. Debian stretch and buster are unfixed and end of life, and Ubuntu 20.04, 18.04 and 16.04 are listed as affected with no fix yet. kernel.org projects end of life for 5.15 and 5.10 in December 2026, so those lines need a supported vendor or a move soon. Appliances and embedded devices on Linux 4.4 or later follow the same rule: ask the vendor in writing whether the device is affected and when a fix ships, and keep its listeners off untrusted networks until then. Until you move, treat every exposed host on these lines as open and apply the stopgaps.

*Sources: kernel.org stable and longterm release pages, Debian and Freexian ELTS trackers, Ubuntu CVE page, SUSE and Oracle Linux advisories*

---

**Q: We patched before the reporters' write-up came out. Could we have been hit earlier?**

**A:** In principle, yes. In practice there is no evidence of it. The fix and its explanation were public from 29 September 2026, 28 days before the reporters' write-up, so anyone reading the commit message could have worked on it. No source reported exploitation at any time, but nothing published lets you tell either way. The reporters published no exploit code, a failed attempt leaves no crash and a successful one is designed not to crash. So check kernel crash records and network telemetry on exposed hosts as far back as retention allows (see ADVANCED FORENSICS). If a crash on an exposed host can't be explained, treat that host's secrets as read and rotate them.

*Sources: netdev mailing list posting of the fix, the reporters' write-up of 27 October 2026, CVE record*

---

**Q: How long does patching take, and will it break things?**

**A:** For most hosts it's a kernel package update, a reboot and some checks. The reboot is the cost: the running kernel stays vulnerable until the host restarts, and a single host with no load balancer needs a maintenance window. A new kernel is a bigger change than a library update, so test that the host boots it and that networking, storage and services come back, and keep the previous kernel installed in case you need to boot back into it. The stopgaps have side effects too. The IP options filter would also drop legitimate traffic on networks that use CIPSO labels on purpose, so count first, then enforce. Turning MPTCP off needs a restart of each listening service before it covers existing listeners. Patch internet-facing hosts with MPTCP listeners or Go services first, watch the first one, then roll out.

*Sources: kernel MPTCP sysctl documentation, RFC 7126, nftables manual*

---

**Q: Should we tell our customers?**

**A:**

- If you patch and find no sign of compromise, this is routine maintenance, and usually no notification is needed.
- If you find indicators of compromise, talk to legal straight away. GDPR, NIS2, CERT-In, HIPAA, SEC and US state laws may all apply, some with deadlines measured in hours.

---

**Q: Should we pay for outside help?**

**A:** Yes if you see any sign of compromise, run many internet-facing Linux hosts across many teams, work in a regulated industry, or are stuck on an end-of-life kernel or an appliance with no vendor fix. Probably not if you have a handful of hosts on distributions that already ship the fix and a team that can patch and reboot today.

---

### For technical teams

**Q: We run dual-stack IPv6 services. Are we exposed over IPv4?**

**A:** Yes, if the socket is bound to `::` without IPV6_V6ONLY. Native IPv6 connections are not affected by the main path, because `tcp_v6_syn_recv_sock()` duplicates the IP options. But IPv4 packets that arrive at a dual-stack socket are handled by the IPv4 code: `tcp_v6_syn_recv_sock()` calls `tcp_v4_syn_recv_sock()` for them. So an IPv4 attacker reaches a dual-stack listener the same way as an IPv4 one. Only IPv6-only sockets, or dual-stack sockets that receive no IPv4, are out of reach. List your listeners with `ss -tlnp` and check each service's settings for IPv6-only mode. The separate IPv6 CALIPSO follow-up is covered in the last question of this section.

*Sources: kernel source (net/ipv6/tcp_ipv6.c), CVE record (CNA: kernel.org)*

---

**Q: We run RHEL, and Red Hat's documentation says MPTCP is off by default. Are we safe?**

**A:** No. If Red Hat's documentation matches your build, the demonstrated MPTCP path is closed, but we didn't test a stock install, and plain TCP stays exposed. The RHEL 8 and 9 documentation says: "By default the MPTCP support is disabled in RHEL." The RHEL 10 guide also tells you to enable it, with no explicit default sentence. MPTCP is built into the Fedora and CentOS Stream configurations, and upstream kernels default `net.mptcp.enabled` to 1, so check what your hosts do instead of trusting the default: run `sysctl net.mptcp.enabled`, and as root `ss -Mlnp`. The Go security team says hosts with no MPTCP listener may be vulnerable to similar attacks, and nobody has publicly shown code execution without one. Red Hat's own bulletin RHSB-2026-016 settles it: RHEL disables MPTCP by default, but having MPTCP enabled is not a precondition, so RHEL is affected anyway. Install the fixed kernel from 1 November (RHSA-2026:93414 for RHEL 8, 93412 for RHEL 9, 93413 for RHEL 10) and reboot. Rocky Linux, AlmaLinux and Oracle's Red Hat compatible kernel have the fix too. OpenShift 4 (RHCOS 8 and 9) was still listed as affected on 4 November. RHEL 6 and 7 are not affected.

*Sources: Red Hat RHEL 8, 9 and 10 documentation, Red Hat CVE page, errata and bulletin RHSB-2026-016, Rocky Linux, AlmaLinux and Oracle Linux errata, kernel MPTCP sysctl documentation, Go security team announcement*

---

**Q: Our services sit behind Cloudflare or another proxy. Are we covered?**

**A:** Partly, and only if the origin can't be reached directly. A proxy that terminates the TCP connection (the Cloudflare proxy, AWS ALB, CloudFront or any reverse proxy) opens its own connection to your origin, so the attacker's IPv4 options never reach your kernel. AWS's bulletin says customers behind ALB, CloudFront, API Gateway and NLB TLS listeners don't receive TCP connections from untrusted sources directly when they follow its best practices, and that Global Accelerator drops every IPv4 packet with IP options. That holds only while the origin is not reachable directly, so lock the origin firewall to the proxy's IP ranges. Services published only through outbound tunnels (Cloudflare Tunnel, for example) have no internet-facing listener. Some limits apply. L4 passthrough load balancers (AWS NLB with TCP listeners, Google Cloud passthrough network load balancers) forward packets, and no documentation says they strip IP options, so treat services behind them as exposed. Cloudflare WAF rules work on HTTP and cannot see IP options. The proxy's own kernel is its operator's problem, not yours. Magic Transit customers can drop packets with options at Cloudflare's edge, because Network Firewall (Magic Firewall) has the fields `ip.hdr_len` and `ip.opt.type`. No AWS, Google Cloud or Azure documentation says their virtual networks drop or strip IPv4 options, and security groups and network ACLs can't match IP options, so treat that as unknown.

*Sources: Cloudflare Network Firewall field reference, AWS bulletin 2026-160-AWS, AWS, Google Cloud and Azure networking documentation (none says their virtual networks strip IP options), our reasoning from how TCP termination works*

---

**Q: What about containers and Kubernetes pods?**

**A:** Containers share the host kernel, so patch and reboot the node. Rebuilding an image changes nothing for this bug. Container-specific points:

1. Every pod or container network namespace starts with `net.mptcp.enabled=1` on upstream kernels, and a host sysctl does not change that. To turn it off, set it inside each running container's namespace (for example `nsenter -t <container-pid> -n sysctl -w net.mptcp.enabled=0`, run as root) or through your platform's sysctl settings. New containers start at 1 again. To list MPTCP listeners inside a container, run `nsenter -t <container-pid> -n ss -Mlnp` as root.
2. kube-proxy and similar L4 forwarding pass packets, IP options included, to pods. An ingress controller that terminates TCP shields the pods behind it, but it is itself exposed. Traefik, for example, is a Go program (see the Go question below).
3. The prerouting hook of the IP options filter also sees traffic that the host forwards to containers. CNI plugins with eBPF datapaths can steer packets past the host's netfilter hooks, so check your CNI's documentation.

*Sources: kernel MPTCP sysctl documentation, kernel source and CVE record, Go security team announcement*

---

**Q: Our scanner is silent. Can we trust a clean report?**

**A:** Not yet. We didn't test any scanner, but several things in the public record would keep one quiet or wrong. NVD showed status "Received" with no NVD score of its own, only the CNA's 9.8. Debian had assigned no urgency. Ubuntu had no notice and no fixed package, and Red Hat and its rebuilds had no fix or advisory, so a tool that waits for a vendor record had nothing to match. Vendor kernels also carry their own version numbers: SUSE's fix for SLES 15 SP6 is on a 6.4.0-based kernel and Oracle's UEK R6 fix is on a 5.4.17-based one, and upstream has no fix for either line, so a scanner that judges by upstream version alone would call both unfixed. Judge vendor kernels by the vendor's advisory and fixed package version. Search for the CVE ID, or for the fix title ("ipv4: free inet_opt and ireq_opt after an RCU grace period"). Until the vendor data catches up, a clean report means little.

*Sources: NVD, Debian and Ubuntu trackers, Red Hat CVE page, SUSE and Oracle Linux advisories, kernel.org release pages*

---

**Q: Why do the scores differ, 9.8 versus 8.1?**

**A:** The split comes down to one metric, attack complexity. The kernel.org CNA scores CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, which is 9.8, and says both racing sides are attacker-induced, so complexity is low. Red Hat scores the race as hard (AV:N/AC:H, draft) and lands on 8.1, with the weakness type CWE-825. SUSE, Amazon Linux and Oracle Linux (preliminary) also say 8.1, and SUSE adds CVSS 4.0 9.2. The reporters' write-up says a lost race only fails the handshake and does not crash the system, so an attacker can keep retrying. NVD showed no score of its own, and GitHub's unreviewed advisory says Critical 9.8. Our position stays the same: critical for internet-facing hosts that accept inbound IPv4 TCP directly, above all with MPTCP listeners, and high everywhere else.

*Sources: kernel.org CVE record, Red Hat, SUSE, Amazon Linux and Oracle Linux pages, NVD, GitHub advisory, the reporters' write-up of 27 October 2026*

---

**Q: I installed the new kernel. Do I still need to reboot?**

**A:** Yes. Rebooting is not optional: the running kernel stays vulnerable until the host restarts, whatever is installed on disk. Check what is running with `uname -r` and compare it with your vendor's fixed version. To see whether a reboot is still pending:

```
# Debian and Ubuntu
cat /var/run/reboot-required
# RHEL family (needs dnf-utils or yum-utils)
needs-restarting -r
# SUSE
zypper needs-rebooting
```

Containers run on the host's kernel, so reboot the node. Live patches exist from three vendors: Oracle Ksplice (UEK R6, R7 and R8, 19 October 2026), SUSE live patching (SLE 12 SP5 and 15 SP4 to SP7) and TuxCare KernelCare (Debian 13 at least). None was found from Ubuntu Livepatch, RHEL kpatch or Amazon Linux. Before you reboot a host you suspect, capture memory and volatile state: a kernel exploit can leave no file on disk, and a reboot destroys memory evidence.

*Sources: Oracle Linux advisories, SUSE CVE page and live patch advisories, TuxCare blog, Ubuntu, Red Hat and Amazon Linux pages (no live patch listed)*

---

**Q: We run Ubuntu and there is no fixed kernel yet. What now?**

**A:** On 4 November Ubuntu had priority critical, no Ubuntu Security Notice and no Livepatch fix. Canonical said on 2 November that the fixes for the generic kernels are in the -proposed pocket for testing, for 22.04 jammy, 24.04 noble, 26.04 resolute and 26.10, and that updates are "the only appropriate mitigation". The aws, azure, gcp, gke and oracle flavours on jammy and noble are still pending. 20.04, 18.04 and 16.04 are "needed" (affected, no fix yet), and 14.04 is not affected. If you run the RHEL family, you're past this question: Red Hat shipped on 1 November, and Rocky Linux, AlmaLinux and Oracle's Red Hat compatible kernel followed. Until Ubuntu's update is released:

1. Find the hosts that accept inbound IPv4 TCP directly, and apply the IP options filter there (count first, then enforce).
2. Where nobody needs MPTCP, turn it off and restart the listening services.
3. Keep `net.ipv4.tcp_migrate_req` at 0 and review `sk_reuseport` BPF programs.
4. Put internet-facing services behind a TCP-terminating proxy, and lock origins to its IP ranges.
5. Watch the vendor's pages, update the day the fix ships, then reboot.

Per-vendor status is under RISK DASHBOARD.

*Sources: Ubuntu CVE tracker and Canonical blog (2 November 2026), Red Hat CVE page and errata, Rocky Linux and AlmaLinux errata, Oracle Linux advisories*

---

**Q: Does the IP options filter fully protect us?**

**A:** No. A Go team member says on Go issue 82717 that dropping IPv4 TCP packets that carry IP options "may suffice", and Red Hat now recommends the filter, but Red Hat also says it "cannot fully prevent" exploitation. Treat the filter as a bridge to the patch, and know its limits:

- It must cover all TCP packets, not only SYNs. Under SYN flood the kernel uses syncookies, and `net/ipv4/syncookies.c` re-reads the options from the final ACK.
- It does nothing for traffic that reaches the host past the netfilter hooks (CNI plugins with eBPF datapaths can do that).
- The rules are not persistent until you add them to your saved ruleset.
- Hosts that use CIPSO labels (NetLabel, multi-level security) carry IP options on purpose, so test before enforcing.
- In nftables, `ip option` matches only lsrr, ra, rr and ssrr and has no timestamp, so the rule matches the header length instead (`ip hdrlength` is the IHL field in 32-bit words, and 5 means no options).
- RFC 7126 recommends dropping Record Route and Timestamp options by default, so legitimate internet traffic with them is rare. Router Alert (used by IGMP and RSVP) is not TCP, so scoping the rule to TCP avoids it.
- `net.ipv4.conf.*.accept_source_route=0` does not help. The kernel checks it only for source-route options (LSRR and SSRR), not for Record Route or Timestamp.

The commands are in the QUICK REFERENCE CARD below (nftables, with an iptables variant that uses the u32 match).

*Sources: Go issue 82717, Go security team announcement, kernel source (net/ipv4/syncookies.c), kernel IP sysctl documentation, nftables manual, iptables extensions manual, RFC 7126*

---

**Q: Is turning off MPTCP enough?**

**A:** No. It closes only the demonstrated path, and plain TCP stays exposed to the underlying bug. `net.mptcp.enabled` controls whether MPTCP sockets can be created. It is per network namespace and defaults to 1. It is checked only when a socket is created, so existing MPTCP listeners keep accepting MPTCP until their service restarts. Go programs fall back to plain TCP automatically.

```
# turn MPTCP off now, then keep it off after a reboot (run as root)
sysctl -w net.mptcp.enabled=0
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-cve-2026-98432.conf
sysctl --system
# then restart services that listen on the network
```

*Sources: kernel MPTCP sysctl documentation, Go security team announcement, Go issue 82717*

---

**Q: What do Go's GODEBUG settings do, and where do they stop?**

**A:** Go programs whose module declares go 1.24 or later open MPTCP listeners by default on Linux, so a Go service can sit on the demonstrated path without anyone choosing that. The Go 1.24 release notes say `ListenConfig` now uses MPTCP by default where supported (currently Linux only). The godebug documentation says `multipathtcp` defaults to "2" in Go 1.24 (listeners only) and that `multipathtcp="0"` reverts to the old behaviour. The values are 0 off, 1 listeners and dialers, 2 listeners only, 3 dialers only. The default applies when the main module's go line is 1.24 or later, and a binary whose module says go 1.23 or lower keeps MPTCP off.

To switch it off for one program:

- Set the environment variable `GODEBUG=multipathtcp=0` in the service definition (if GODEBUG already exists, append it with a comma), then restart the service.
- Or rebuild with `godebug multipathtcp=0` in go.mod (Go 1.23 and later), or `//go:debug multipathtcp=0` in the main package (Go 1.21 and later).

Where it stops:

- The GODEBUG environment variable overrides go.mod and `//go:debug` settings, and an explicit `SetMultipathTCP(true)` in code overrides GODEBUG, so none of this stops a program that asks for MPTCP itself.
- It closes only the demonstrated path. The Go security team says the bug is not specific to MPTCP, calls the per-program approach "a fragile mitigation", says the best fix is a patched kernel and says it is premature to change Go's defaults. Go issue 82717 was still undecided on 4 November 2026.
- If the kernel refuses MPTCP sockets (for example `net.mptcp.enabled=0` gives ENOPROTOOPT), Go silently falls back to plain TCP, so the host-wide sysctl needs no change in the programs.

To see what a binary will do, run `go version -m /path/to/binary`. It needs a Go toolchain, and a directory is scanned recursively. The "build DefaultGODEBUG=..." line appears only when it is not empty, and a binary whose module declares go 1.24 or later and shows no multipathtcp=0 there opens MPTCP listeners by default.

Common Go servers: we checked the go.mod of each project's latest release on 30 October 2026. All declare go 1.24 or later with no godebug override that turns MPTCP off, so they open MPTCP listeners by default wherever the kernel allows it: Caddy v2.11.7, Traefik v3.7.16, Kubernetes v1.37.2 (it declares "godebug default=go1.26", which keeps the 1.24+ default), k3s v1.37.1+k3s1, etcd v3.7.3, Prometheus v3.15.1, Grafana v13.3.0, Gitea v28.2.0, Vault v2.2.1, Consul v2.1.0, CoreDNS v1.15.0, Mattermost v12.0.1, NATS Server v2.15.2, Argo CD v3.5.6, MinIO RELEASE.2025-10-15T17-29-55Z, Headscale v0.29.6, frp v0.71.1 and Distribution (container registry) v3.1.2. This comes from go.mod only. We didn't audit each program's code, and a program can opt out per socket. mptcp.dev (secondary) also lists Caddy since v2.10.0, and Traefik since v2.11.26 and v3.4.2, as MPTCP by default on the server side. Opt-in only: systemd sockets (SocketProtocol=mptcp), mptcpize and lighttpd (server.network-mptcp defaults to "disable"). Per mptcp.dev (secondary), HAProxy 3.1, NGINX 1.29.7, Apache, Envoy and Valkey 9 need explicit configuration.

*Sources: Go 1.24 release notes, Go GODEBUG documentation, Go security team announcement, Go issue 82717, go.mod files of the releases named, mptcp.dev application list (secondary)*

---

**Q: Do request migration and BPF reuseport programs matter?**

**A:** Yes, they open a second path to the same bug. Request socket migration is enabled by `net.ipv4.tcp_migrate_req=1` or by a BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program, and the cloned and old request sockets then share the same options. The migration code came in with commit `c905dee62232` ("tcp: Migrate TCP_NEW_SYN_RECV requests at retransmitting SYN+ACKs."), authored 12 June 2021 and first released in Linux 5.14. Keep `net.ipv4.tcp_migrate_req=0`, which is the default. A BPF program migrates requests regardless of the sysctl. `bpftool prog show` lists sk_reuseport programs but can't show whether one is the migrating kind, so treat any sk_reuseport program as a candidate.

```
# reuseport BPF programs that could migrate requests (run as root)
bpftool prog show | grep sk_reuseport
```

*Sources: kernel.org CVE record, kernel mainline history for the migration commit, kernel IP sysctl documentation*

---

**Q: Our host logged a kernel panic or oops. Is it this bug?**

**A:** Look at what the log names. The kernel prints "skb_under_panic: text:... len:... put:... head:... data:... tail:... end:... dev:..." before a panic. An oops that names `ip_options_build` or `ip_build_and_send_pkt` is a strong sign of attempts. KASAN reports ("BUG: KASAN: ...") appear only on kernels built with CONFIG_KASAN. Clean logs prove nothing: a lost race leaves no crash, and a successful exploit is designed not to crash.

```
# search the kernel log for crash signs
journalctl -k -g 'ip_options_build|skb_under_panic|KASAN'
dmesg | grep -E 'ip_options_build|skb_under_panic|KASAN'
```

The reporters' write-up says the payload ends by running a shell command as root from kernel context. Commands that the kernel starts through its user-mode helper normally have a kernel thread as parent, usually kthreadd (PID 2). Legitimate helpers (modprobe, coredump and hotplug helpers) show up too, so baseline first. This is general kernel-exploit hunting, not specific to this exploit.

```
# user-space processes whose parent is kthreadd (kernel threads show their name in brackets)
ps -eo pid,ppid,user,lstart,args | awk '$2 == 2 && $9 !~ /^\[/'
```

DETECTION & FORENSICS has the log patterns and the network rules.

*Sources: the reporters' write-up of 27 October 2026, kernel log message formats (skb_under_panic, KASAN)*

---

**Q: Are the public GitHub repositories safe to run for testing?**

**A:** Don't. 71 GitHub repositories mentioned the CVE on 4 November, up from 11 on 30 October. None is verified. Their descriptions include checkers, mitigations, audits, a livepatch, a trigger that says it does no code execution, and a "lab root-shell kit" that says it is not a stock remote exploit. Running unknown code is a common way to get compromised, above all as root on a production host, and a "checker" is code you would run with full privileges. We name none of them here. Use the read-only commands in this document, your vendor's advisories and the version checks instead. If you must test, use an isolated lab VM with no route to production.

*Sources: GitHub repository search for the CVE ID (names withheld)*

---

**Q: Is the fix complete? What is the IPv6 CALIPSO follow-up?**

**A:** For the IPv4 bug, the kernel update is the fix, and the Go security team calls a patched kernel the best fix. The bug was reported by Xinyang Ge. The mainline fix is commit `e3f33b0a1d89d738e2b913dab519226eaf76e15b`, and it shares its title with the CVE ("ipv4: free inet_opt and ireq_opt after an RCU grace period"). Eric Dumazet wrote it, Jakub Kicinski committed it on 5 October 2026 and Kuniyuki Iwashima reviewed it. It makes two one-line changes, using `kfree_rcu()` in `inet_sock_destruct()` and in `tcp_v4_reqsk_destructor()`. It had no "Cc: stable" tag but was backported to every maintained line.

One item is open. The CVE text says `tcp_v6_reqsk_destructor()` has the same migration issue with `ipv6_opt`, which only CALIPSO sets, and that a separate patch will fix it. As of 30 October 2026 there is no maintainer patch and no CVE for it. A third party proposed a fix on the netdev list on 19 October 2026 (secondary). The exposed combination looks narrow, because it needs CALIPSO and request migration, but we haven't verified that. If you use CALIPSO, watch for the patch and keep `net.ipv4.tcp_migrate_req` at 0.

*Sources: kernel mainline commit, kernel.org CVE record, netdev mailing list posting of the fix, Go security team announcement*

---

## SUCCESS CRITERIA & VERIFICATION

### You have successfully responded when:

**Technical validation checklist:**

- [ ] **All Linux hosts inventoried:**
    - Hosts, VMs, Kubernetes nodes, cloud images and autoscaling templates, appliances and embedded devices
    - Distribution, running kernel version, listening ports, MPTCP setting and exposure path recorded for each
- [ ] **All exposed hosts patched:**
    - Running kernel at or above the fixed version for its line (7.2.10, 6.18.56, 6.12.113, 6.6.159, 6.1.190, 5.15.223, 5.10.272, 7.3), or a vendor kernel that its advisory lists as fixed
    - Where the vendor has no fix yet: stopgaps in place, and a dated task to patch the day the fix ships
    - End-of-life kernels and distributions upgraded, isolated or offline
    - Appliances: the vendor's answer in writing, and compensating controls until the fix ships
- [ ] **All patched hosts rebooted:** the running kernel is the fixed one, and the boot time is later than the install time
- [ ] **Verification passes:**

    ```bash
    # running kernel version: compare with the fixed versions or your vendor's advisory
    uname -r
    # installed kernel package version (Debian and Ubuntu)
    dpkg -s linux-image-$(uname -r) | grep '^Version'
    # installed kernel packages (RHEL family, Fedora, Amazon Linux, Oracle, SUSE)
    rpm -qa 'kernel*' | sort
    # when the host booted: start time of PID 1
    ps -p 1 -o lstart=
    # is a reboot still pending? (Debian and Ubuntu)
    cat /var/run/reboot-required
    # is a reboot still pending? (RHEL family, needs dnf-utils or yum-utils)
    needs-restarting -r
    # is a reboot still pending? (SUSE)
    zypper needs-rebooting
    # MPTCP and migration settings
    sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req
    # MPTCP listening sockets in the current network namespace, with processes (run as root)
    ss -Mlnp
    # the options filter and its counter, if you applied it (run as root)
    nft list table ip cve_98432
    ```

- [ ] **No indicators of compromise** (see the checklist under DETECTION & FORENSICS)
- [ ] **Defense in depth:**
    - [ ] Origins locked to the TCP-terminating proxy's IP ranges, where you rely on a proxy
    - [ ] Inbound TCP with IP options counted or alerted on (nftables counter, or a Suricata or Snort rule)
    - [ ] `net.ipv4.tcp_migrate_req` still 0, and sk_reuseport BPF programs reviewed
    - [ ] MPTCP off where nobody needs it
    - [ ] Detection rules live (kernel crash signs, unexpected commands started by the kernel)
    - [ ] Log retention extended for forensics

---

**Operational validation checklist:**

- [ ] **Services work:** hosts boot, networking and storage come up, services start, and logins, health checks, backups and monitoring agents are tested
- [ ] **No new boot failures, crash loops or 5xx spikes** after the reboot
- [ ] **Stopgaps cleaned up:** the options filter removed, or kept on purpose and saved to the ruleset (CIPSO networks checked); the MPTCP switch kept on purpose or reverted; GODEBUG settings removed or kept on purpose
- [ ] **Documentation done:** timeline, kernel versions before and after, reboot times
- [ ] **Stakeholders updated:**
    - [ ] Leadership briefed
    - [ ] Legal told whether any compromise was found
    - [ ] Insurer told the remediation is complete

---

**Compliance validation checklist:**

- [ ] **Audit trail kept:** every action timestamped, every decision explained
- [ ] **Evidence preserved** where there was any doubt
- [ ] **Breach decision documented:** legal agrees on whether notification is needed, and the evidence supports that conclusion

---

### Post-incident review checklist

**Hold within a week of finishing:**

- [ ] **What went well:**
    - Time from the public fix or CVE record to patch
    - How fast you found every Linux host and appliance
- [ ] **What needs work:**
    - Gaps in the inventory (appliances, embedded devices, container nodes, cloud images, autoscaling templates)
    - Reboot procedures and maintenance windows
    - How many hosts waited on a vendor with no fix
    - Contacts at hosting providers, cloud providers and appliance vendors
- [ ] **Metrics captured:**
    - Time to inventory: [X hours from the day you learned of it]
    - Time to patch: [X hours]
    - Time to verified reboot: [X hours]
    - Systems affected: [X]
    - Staff hours: [X]
- [ ] **Actions:**
    - Retire end-of-life kernels and distributions
    - Keep the host and appliance inventory current
    - Add reboot verification to the patch process
    - Rebuild golden images and node images on a schedule instead of waiting for an advisory

---

## ADDITIONAL RESOURCES

### Official security advisories

- **CVE record:** https://www.cve.org/CVERecord?id=CVE-2026-98432 (published 15 October 2026, 12:08 UTC, CNA: kernel.org; CVSS 3.1 9.8 added 24 October 2026, 14:08 UTC)
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-98432 (status still "Received" on 4 November, no NVD score of its own, shows the CNA 9.8)
- **Mainline fix:** https://git.kernel.org/stable/c/e3f33b0a1d89d738e2b913dab519226eaf76e15b
- **Fix on the netdev list (v2, 1 October 2026):** https://lore.kernel.org/r/20261001221253.2964024-1-edumazet@kernel.org
- **IPv6 sibling fix (posted 3 November 2026, under review on 4 November):** https://marc.info/?l=linux-netdev&m=179369697364876&w=2
- **kernel.org releases:** https://www.kernel.org/category/releases.html (fixed in 7.3, 7.2.10, 6.18.56, 6.12.113, 6.6.159, 6.1.190, 5.15.223 and 5.10.272; newest on 4 November 2026: mainline 7.4-rc1, stable 7.3.1, longterm 6.18.60, 6.12.115, 6.6.161, 6.1.191, 5.15.224 and 5.10.273; 7.2 ended with 7.2.15 on 1 November)
- **Kernel documentation:** MPTCP sysctls https://docs.kernel.org/networking/mptcp-sysctl.html and IP sysctls https://docs.kernel.org/networking/ip-sysctl.html
- **GitHub advisory:** https://github.com/advisories/GHSA-qp6h-4hvh-qqqc (published 15 October 2026, 18:32 UTC, unreviewed, rated critical 9.8)

### Government and CERT advisories

- **CISA:** the CVE is not in the KEV catalog (catalog 2026.11.03): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **NCSC-NL:** NCSC-2026-0461 (30 October 2026): https://advisories.ncsc.nl/csaf/v2/2026/ncsc-2026-0461.json
- **Canadian Centre for Cyber Security:** AV26-1108 (30 October 2026): https://cyber.gc.ca/en/alerts-advisories/linux-security-advisory-av26-1108
- **CERT-FR:** CERTFR-2026-AVI-1432 (30 October 2026): https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1432/
- **HKCERT:** bulletins for the Debian, Red Hat and SUSE kernels (3 November 2026), for example https://www.hkcert.org/security-bulletin/redhat-linux-kernel-multiple-vulnerabilities_20261103
- **No advisory found by 4 November:** the CISA and NCSC UK feeds. BSI, ACSC, CERT-In, JPCERT/CC and CERT-EU couldn't be checked properly
- **Cloud providers:** AWS bulletin 2026-160-AWS (31 October 2026): https://aws.amazon.com/security/security-bulletins/2026-160-aws/. No Google Cloud or GKE bulletin names the CVE. Microsoft's update guide lists it for Azure Linux with customer action required (link under Vendor and distro advisories)
- **oss-security:** the Go announcement was forwarded on 30 October 2026 (00:21 UTC): https://www.openwall.com/lists/oss-security/2026/10/30/1. CISA's ADP container added the oss-security link to the CVE record (02:08 UTC). Later posts cover `net.mptcp.enabled=0` (30 October), `init_on_free=1` as a stopgap (31 October) and a CIQ kernel engineer's reply that it doesn't help (3 November): https://www.openwall.com/lists/oss-security/2026/10/30/6, https://www.openwall.com/lists/oss-security/2026/10/31/5 and https://www.openwall.com/lists/oss-security/2026/11/03/1

### Research and threat intelligence

- **The reporters' write-up (27 October 2026, updated 28 October 2026):** the write-up published by the team that reported the bug, not linked here. It describes remote root command execution against servers with an MPTCP listener, and it names no tested kernel versions or distributions
- **Go security team (golang-announce, 29 October 2026, 23:34 UTC):** https://groups.google.com/g/golang-announce/c/PCoQcdxoScw/m/aD-MgXEvAAAJ
- **Go issue 82717, "proposal: net: Disable MPTCP by default" (opened 29 October 2026, still undecided on 4 November 2026):** https://go.dev/issue/82717
- **Red Hat bulletin RHSB-2026-016 (last updated 4 November 2026):** https://access.redhat.com/security/vulnerabilities/RHSB-2026-016
- **Canonical (2 November 2026):** https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432
- **AlmaLinux (30 October 2026, updated 2 November):** https://almalinux.org/blog/2026-10-30-cve-2026-98432/
- **TuxCare:** https://tuxcare.com/blog/cve-2026-98432-linux-tcp-remote-root/
- **Previdian exploitation tracker:** https://previdian.com/CVE-2026-98432
- **Go GODEBUG documentation:** https://go.dev/doc/godebug
- **Go 1.24 release notes:** https://go.dev/doc/go1.24
- **The Hacker News (29 October 2026):** "Linux Kernel TCP Flaw With 9.8 CVSS Score Affects Ubuntu, Red Hat and Other Distributions", https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html
- **The Hacker News (3 November 2026):** "Red Hat Patches 9.8-Rated Linux TCP RCE Flaw While Ubuntu Releases Fixes for Testing", https://thehackernews.com/2026/11/red-hat-patches-98-rated-linux-tcp-rce.html
- **BleepingComputer (30 October 2026):** https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/
- **MPTCP application list (secondary):** https://www.mptcp.dev/apps.html
- **Exposure counts:** no public counts exist, and this document gives none

### Detection and scanning tools

- **Checkers:** this analysis has no checker script. Use the read-only commands under AM I AFFECTED? SELF-ASSESSMENT and DETECTION & FORENSICS
- **Exploit tracking:** Rapid7 lists exploited_in_wild as false (https://www.rapid7.com/db/vulnerabilities/cve-2026-98432/), EPSS is 0.0076 at the 55.3rd percentile on 3 November 2026 (https://api.first.org/data/v1/epss?cve=CVE-2026-98432), Previdian says "No Exploitation Yet", and CISA KEV does not list the CVE (catalog 2026.11.03)
- **Fortinet:** PSIRT FG-IR-26-188 (2 November 2026): https://fortiguard.fortinet.com/psirt/FG-IR-26-188. FortiGuard lists IPS signature Linux.Kernel.tcp_v4_syn_recv_sock.Use.After.Free from 3 November
- **Tenable:** 73 plugins on 4 November 2026: https://www.tenable.com/cve/CVE-2026-98432/plugins
- **No rule or template yet:** no Emerging Threats Open or Snort community rule names the CVE, and nuclei has no template (checked on 4 November 2026)
- **Vendor filter rules:** Red Hat bulletin RHSB-2026-016 (nftables), AlmaLinux's blog post (nftables) and AWS bulletin 2026-160-AWS (iptables u32 and AWS Network Firewall). All three are stopgaps
- **OSV:** https://osv.dev/vulnerability/CVE-2026-98432
- **Network rules:** Suricata and Snort 3 both have an `ipopts` keyword (Snort 3: https://docs.snort.org/rules/options/non_payload/ipopts). Suricata accepts rr, eol, nop, ts, sec, esec, lsrr, ssrr, satid, qs, rtralt, cipso or any, one per rule. Example rules are under DETECTION & FORENSICS
- **nftables manual:** https://www.netfilter.org/projects/nftables/manpage.html
- **iptables extensions (u32 match):** https://ipset.netfilter.org/iptables-extensions.man.html
- **RFC 7126:** https://www.rfc-editor.org/rfc/rfc7126 (recommends dropping Record Route and Timestamp options by default)
- **Cloudflare Network Firewall (Magic Firewall) fields:** https://developers.cloudflare.com/magic-firewall/reference/magic-firewall-fields/ (`ip.hdr_len` and `ip.opt.type`, for Magic Transit customers; Cloudflare WAF rules work on HTTP and can't see IP options)
- Treat GitHub repositories that claim to be proofs of concept as unreviewed and untrusted

### Vendor and distro advisories

- **Debian:** https://security-tracker.debian.org/tracker/CVE-2026-98432 (fixed in bookworm linux 6.1.190-1 (DLA-4841-1) and linux-6.12 6.12.113-1~deb12u1 (DLA-4850-1), trixie 6.12.113-1 (DSA-6568-1), forky 7.2.12-1 and sid 7.2.13-1; stretch and buster end of life; urgency not yet assigned)
- **Debian ELTS (Freexian):** https://deb.freexian.com/extended-lts/tracker/CVE-2026-98432 (bullseye: 5.10.272-1, ELA-1846-1, and linux-6.1 6.1.190-1~deb11u1, ELA-1850-1; the tracker also lists linux-6.1 as fixed for stretch and buster, not checked further)
- **Ubuntu:** https://ubuntu.com/security/CVE-2026-98432 (priority critical since 3 November, no Ubuntu Security Notice yet; fixes in -proposed for 22.04, 24.04, 26.04 and 26.10; 20.04, 18.04 and 16.04 needed; 14.04 not affected; no Livepatch fix listed)
- **Red Hat:** https://access.redhat.com/security/cve/CVE-2026-98432 (Critical 9.8; RHEL 8, 9 and 10 fixed on 1 November by RHSA-2026:93414, 93412 and 93413, with EUS, E4S, AUS, TUS and SAP errata after them; OpenShift 4 still affected; RHEL 6 and 7 not affected)
- **Red Hat Bugzilla:** https://bugzilla.redhat.com/show_bug.cgi?id=2553390 (status still NEW, no kpatch)
- **Rocky Linux:** https://errata.rockylinux.org/ (RLSA-2026:93414, 93412 and 93413, 3 November 2026)
- **AlmaLinux:** https://errata.almalinux.org/ (ALSA-2026:93414 and 93415 for AlmaLinux 8; fixed kernels for 9 and 10 in the repositories since 2 November)
- **Red Hat MPTCP guide (RHEL 9):** https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/getting-started-with-multipath-tcp_configuring-and-managing-networking
- **SUSE:** https://www.suse.com/security/cve/CVE-2026-98432.html (important; fixed kernel-default at least 6.12.0-160000.40.1 for SLE 16.0 and SLE Micro 6.2, 6.4.0-150700.53.90.1 for SLES 15 SP7, 6.4.0-150600.23.143.1 for SLES 15 SP6 LTSS, 5.14.21-150500.55.195.1 for SLES 15 SP5 LTSS and Micro 5.5, 5.14.21-150400.24.246.1 for SLES 15 SP4 LTSS and Micro 5.3 and 5.4; SLE Micro 6.0 and 6.1 released; SLES 12 SP5 in progress; live patches for SLE 12 SP5 and 15 SP4 to SP7; SLE 11 SP4 not affected)
- **Amazon Linux:** https://explore.alas.aws.amazon.com/CVE-2026-98432.html (Important, CVSS 8.1; AL2023 kernel6.12 6.12.113-138.209.amzn2023 (ALAS2023-2026-3335), kernel6.18 6.18.56-125.164.amzn2023 (ALAS2023-2026-3251) and kernel 6.1.189-236.400 (ALAS2023-2026-3365); AL2 kernel 4.14.355-287.758 (ALAS2-2026-4065) and the 5.4, 5.10 and 5.15 extras; AL2 is marked end of support; no live patch)
- **Oracle Linux:** https://linux.oracle.com/cve/CVE-2026-98432.html (UEK fixed 16 October 2026: ELSA-2026-500397 for UEK R6 5.4.17-2136.360.3.1, ELSA-2026-500398 for UEK R7 5.15.0-325.221.6.4 and ELSA-2026-500399 for UEK R8 6.12.0-207.111.5.4, then newer UEK errata ELSA-2026-500572 to -500574 on 2 November; RHCK fixed on 2 November: ELSA-2026-93414, -93412 and -93413; Ksplice updates on 19 October 2026)
- **Microsoft (Azure Linux):** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-98432 (Azure Linux 3.0 kernel 6.6.159.1-1.azl3, in the production repository since 20 October 2026; Azure Linux 4.0 under investigation; customer action required)
- **Alpine:** https://security.alpinelinux.org/vuln/CVE-2026-98432 (the tracker still has no package data; linux-lts 6.12.114 on 3.21 and 3.22 and 6.18.59 on 3.23, 3.24 and edge are at or above the fix (inferred))
- **GKE security bulletins:** https://cloud.google.com/kubernetes-engine/security-bulletins (none names the CVE on 4 November)
- **Container-Optimized OS release notes:** https://cloud.google.com/container-optimized-os/docs/release-notes (the m121, m125, m129 and m133 notes name the fix, m133 in cos-133-19999-44-174)
- **EKS AMI releases:** https://github.com/awslabs/amazon-eks-ami/releases (AL2023 AMI v20261031 fixed, per AWS bulletin 2026-160-AWS)
- **Bottlerocket releases:** https://github.com/bottlerocket-os/bottlerocket/releases (v1.68.1, 2 November 2026, with kernel-kit 9.6.2, has the fix)
- **AKS releases:** https://github.com/Azure/AKS/releases (node image 202610.23.0 rolled out, kernels not confirmed; 202610.16.1 was below the fix)
- **Flatcar releases:** https://www.flatcar.org/releases (stable 4757.2.2 and later, LTS 4081.3.11 and later, fixed (inferred))
- **Talos releases:** https://github.com/siderolabs/talos/releases (v1.14.3 and later, fixed (inferred))
- Fedora 44 kernel 7.2.15, Arch linux 7.2.14 and Arch linux-lts 6.18.60 are fixed (inferred from their kernel versions). CentOS Stream 9 and 10 had no fixed kernel on 4 November

### Emergency support contacts

- **Appliance and embedded device vendors:** the vendor's security contact (not an incident hotline)
- **CISA:** report@cisa.gov or +1 888-282-0870
- **FBI Internet Crime Complaint Center (IC3):** report online (US)
- **CERT-In (India):** incident@cert-in.org.in or 1800-11-4949
- **NCSC-UK:** its online incident reporting service
- **Your hosting provider's security contact, your Linux distributor's security team and your incident response retainer**

---

## QUICK REFERENCE CARD

### Print and post this

```
===============================================================
  TCP2SHELL (CVE-2026-98432): REMOTE USE-AFTER-FREE IN LINUX
     CVSS 3.1 9.8 (kernel.org) | Distros: 8.1 Important
===============================================================

FIXED UPSTREAM (first fixed release on each line):
  7.3 (7.3-rc7, then 7.3 on 18 October 2026)
  7.2.10 and 6.18.56 (11 October 2026)
  6.12.113  6.6.159  6.1.190  5.15.223  5.10.272 (15 October 2026)
  Vendor kernels: judge by the vendor's advisory and fixed
  package version, not by the upstream number

NO UPSTREAM FIX (vendor backport only):
  5.4 and older, and end-of-life lines such as 7.1, 7.0, 6.19
  Appliances and embedded devices on 4.4 or later: ask the vendor

NOT AFFECTED:
  Kernels older than 4.4, RHEL 6 and 7, SLE 11 SP4, Ubuntu 14.04

NO RELEASED FIX ON 4 NOVEMBER 2026 (partial list):
  Ubuntu 22.04 and later (in testing), 20.04 and older
  (needed), OpenShift 4, CentOS Stream 9 and 10, SLES 12 SP5
  (in progress). AKS node image: kernels not confirmed
  RHEL 8, 9 and 10, Rocky, AlmaLinux, Oracle RHCK, SLES 15 SP7,
  Amazon Linux 2, EKS and Bottlerocket are fixed now

---------------------------------------------------------------
YOU ARE EXPOSED WHEN ALL OF THESE ARE TRUE:
---------------------------------------------------------------

  1. Kernel 4.4 or later, below the fix
  2. A listening TCP port that an attacker can reach over IPv4
     (dual-stack IPv6 listeners count: :: without IPV6_V6ONLY)
  3. IPv4 options survive the path to the host (our reasoning:
     a TCP-terminating proxy stops them; L4 passthrough and
     kube-proxy do not)

  Demonstrated path: an MPTCP listener. Go programs whose go.mod
  says go 1.24 or later open them by default. Nobody has shown
  code execution without MPTCP, but the Go security team says
  similar attacks may work

---------------------------------------------------------------
IMMEDIATE ACTIONS:
---------------------------------------------------------------

1. CHECK (1 minute):
   $ uname -r                    # compare with the fixed versions
   $ sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req
   $ ss -tlnp                    # all TCP listening sockets
   $ ss -Mlnp                    # MPTCP listeners, run as root

2. PATCH (internet-facing hosts with MPTCP listeners or Go
   services first), all run as root:
   Debian, Ubuntu:   apt update && apt full-upgrade
   RHEL family, Fedora, Oracle Linux:   dnf upgrade 'kernel*'
   Amazon Linux 2023:   dnf upgrade --releasever=latest 'kernel*'
   SUSE:   zypper patch
   Containers: patch the node, not the image

3. REBOOT EVERY HOST (run as root):
   $ systemctl reboot
   The running kernel stays vulnerable until the reboot.
   Still pending?  cat /var/run/reboot-required (Debian, Ubuntu)
                   needs-restarting -r (RHEL family)
                   zypper needs-rebooting (SUSE)

4. CAN'T PATCH TODAY? These are bridges, not fixes.

   a) Drop inbound IPv4 TCP packets that carry IP options.
      Red Hat recommends it, and says it reduces exposure
      but cannot fully prevent an attack.
      Count first, then enforce:

      # run as root
      nft add table ip cve_98432
      nft add chain ip cve_98432 pre '{ type filter hook prerouting priority raw; policy accept; }'
      nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter
      # watch the counter: on normal traffic it should stay near zero
      nft list table ip cve_98432
      # then enforce
      nft add rule ip cve_98432 pre ip protocol tcp ip hdrlength != 5 counter drop
      # rollback
      nft delete table ip cve_98432

      iptables alternative (u32 match):

      # run as root
      iptables -t raw -I PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP
      # check hits
      iptables -t raw -L PREROUTING -v -n
      # rollback
      iptables -t raw -D PREROUTING -p tcp -m u32 --u32 "0>>22&0x3C=21:60" -j DROP

      Rules are not persistent. Hosts that use CIPSO labels
      carry IP options on purpose: test first

   b) Turn MPTCP off. This closes only the demonstrated path:

      # run as root
      sysctl -w net.mptcp.enabled=0
      echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-cve-2026-98432.conf
      sysctl --system
      # then restart services that listen on the network

      Containers: set it in each container's network namespace
      (nsenter -t <container-pid> -n sysctl -w net.mptcp.enabled=0,
      run as root). New containers start at 1 again

   c) Go services: set GODEBUG=multipathtcp=0 and restart
      (append with a comma if GODEBUG exists). Fragile:
      SetMultipathTCP(true) in code overrides it

   d) Put services behind a TCP-terminating proxy and lock the
      origin to the proxy's IP ranges. Keep net.ipv4.tcp_migrate_req=0

---------------------------------------------------------------
WHAT TO WATCH (the reporters' pattern; they published no exploit code):
---------------------------------------------------------------

  Inbound TCP with IP options (near zero on internet links)
  Many handshakes from one source over tens of minutes (48
  minutes in the reporters' proof of concept), with Record Route
  or Timestamp options and retransmitted SYNs
  Kernel log: skb_under_panic, or an oops naming ip_options_build
  or ip_build_and_send_pkt. KASAN reports only on CONFIG_KASAN
  Commands started by the kernel (parent kthreadd, PID 2).
  Baseline first: modprobe, coredump and hotplug helpers show up
  Clean logs prove nothing. A lost race leaves no crash

---------------------------------------------------------------
THREAT LEVEL (4 November 2026):
---------------------------------------------------------------

  No exploitation in the wild reported
  Reporters' write-up (27 October): remote root command execution
  against servers with an MPTCP listener. 48 minutes to leak a
  kernel pointer, 5 more to run a command
  The reporters published no exploit code. 71 GitHub
  repositories mention the CVE, none verified: do not run them
  Not in CISA KEV. EPSS 0.0076 (55.3rd percentile)
  Red Hat: MPTCP is not a precondition. Now 9.8 Critical

---------------------------------------------------------------
IF COMPROMISED:
---------------------------------------------------------------

  1. Isolate the host (keep it running for evidence)
  2. Capture memory and volatile state BEFORE any reboot or
     patch. Preserve logs. Do NOT delete anything
  3. Rotate every secret the host could read
  4. Bring in incident response, legal and your insurer
  5. Contact: [Your security team / CISO]

---------------------------------------------------------------
MORE INFORMATION:
---------------------------------------------------------------

  Kernel fix:  mainline commit e3f33b0a1d89
  Go team:     golang-announce, 29 October 2026, Go issue 82717
  Reporters:   the write-up published by the team that reported
               the bug (27 October 2026)
  Vendors:     the CVE page of your distribution (see
               ADDITIONAL RESOURCES)

  Emergency Support: [Your IT Security Contact]
  Phone: [Phone Number]
  Email: [Email Address]

===============================================================
     A fixed kernel on disk with the old kernel still running
              is not fixed. Patch, then reboot.
===============================================================

Document Version: 1.1
Last Updated: 4 November 2026
Classification: TLP:CLEAR, public distribution
```

*Sources: kernel.org CVE record, Go security team announcement, the reporters' write-up of 27 October 2026, Debian, Ubuntu, Red Hat, SUSE, Amazon Linux and Oracle Linux advisories. Details are in the sections above.*

---

## FINAL RECOMMENDATIONS

### The bottom line

**If your hosts run a kernel at or above the fixed version for their line, or a vendor kernel that its advisory lists as fixed, and every host has rebooted:**

- You're fixed for this CVE
- Keep the detection rules on: inbound TCP with IP options, kernel crash signs
- If you use CALIPSO, watch for the separate IPv6 patch, posted on 3 November and still under review on 4 November
- Ignore a scanner that judges vendor kernels by the upstream version alone

**If you run an unpatched kernel and accept inbound IPv4 TCP from the internet:**

- Patch and reboot today, internet-facing hosts with MPTCP listeners or Go services first
- Where a reboot has to wait, apply the IP options filter (Red Hat says it reduces exposure but can't fully prevent an attack) and turn MPTCP off. Both are bridges, not fixes
- Check your kernel logs and network telemetry as far back as retention allows

**If you run Ubuntu:**

- The fix was still in testing (-proposed) on 4 November, with no Ubuntu Security Notice
- Apply the stopgaps, watch Ubuntu's page, and patch and reboot the day the update is released

**If you run RHEL 8, 9 or 10, or a rebuild such as AlmaLinux, Rocky Linux or Oracle's Red Hat compatible kernel:**

- The fix shipped between 1 and 3 November. Install it and reboot. OpenShift 4 was still listed as affected on 4 November

**If a cloud or managed Kubernetes service runs your nodes:**

- Get a written answer about the kernel your nodes run, and roll the nodes onto a fixed image. On 4 November the EKS AL2023 AMI v20261031 and Bottlerocket v1.68.1 were fixed, and the kernels of the newest AKS node image weren't confirmed

**If you run an end-of-life kernel, a distribution with no fix or an appliance waiting on its vendor:**

- This is the hard case, because no upstream fix exists for 5.4 and older
- Ask the vendor in writing, take listeners off untrusted networks, filter in front of the device and plan its replacement

**If you don't know what Linux you run:**

- Find out in the next two hours. Start with the inventory commands under AM I AFFECTED? SELF-ASSESSMENT

### Takeaway for leadership

CVE-2026-98432 is easy to underestimate and hard to scope. Its severity label depends on who you ask: the kernel.org CNA and now Red Hat say 9.8, SUSE, Amazon and Oracle still say 8.1, and the gap is whether the timing race is hard. The reporters say a lost race only fails the handshake, so an attacker can retry. Exposure depends on things most teams haven't mapped: which hosts accept inbound IPv4 TCP directly, whether a proxy that terminates TCP sits in front, and which services open MPTCP listeners (Go programs whose go.mod says go 1.24 or later do by default). Whether code execution works without an MPTCP listener is not known publicly. The Go security team says similar attacks may be possible, so don't wait for that answer. The timing is not in dispute. The fix and its explanation were public from 29 September 2026, 16 days before the CVE record and 28 days before the reporters' write-up. A fix needs a reboot, so a host stays exposed until it restarts. Red Hat shipped 17 days after the CVE record, and on day 20 Ubuntu's fix was still in testing.

Use the incident to fix four things:

1. Know every Linux host and appliance that accepts inbound IPv4 TCP, and which kernel runs on it
2. Know which services open MPTCP listeners, including Go programs that do it by default
3. Retire end-of-life kernels, distributions and appliances with no vendor fix, or isolate them
4. Treat reboots as part of patching, and make rolling reboots routine

### Remember

- The fix and its explanation were public 16 days before the CVE record and 28 days before the reporters' write-up
- A patch only counts once the host has rebooted
- Vendor kernels keep their own version numbers, so judge them by the vendor's advisory
- Turning MPTCP off closes only the demonstrated path, and the IP options filter reduces exposure without fully preventing an attack
- A TCP-terminating proxy shields an origin only while the origin is locked to it
- Clean logs prove little: a lost race leaves no crash
- Don't run the public repositories named after the CVE
- Patch first, argue about 9.8 versus 8.1 later

**Patch the kernel today. Reboot every host today.**

---

**Document Version:** 1.1
**Last Updated:** 4 November 2026
**Data cut-off:** 4 November 2026, 14:00 UTC (version 1.0: 30 October 2026, 06:30 UTC)
**Classification:** TLP:CLEAR, public distribution
**Prepared by:** 0xDTC (TheSecureLancer)

Facts in this document come from kernel.org and the CVE record, distro and cloud advisories, the Go security team, standards and tool documentation, and press coverage listed above. Where those sources disagree, the document says so.
