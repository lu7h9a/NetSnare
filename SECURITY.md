# Security policy

## Reporting a vulnerability

Please report security problems privately through **GitHub Security
Advisories**: open the **Security** tab of this repository and choose
**Report a vulnerability**. Please do not open a public issue for a security
problem.

Include the Python version, your Linux distribution, what an attacker can
do, and steps or a packet capture that reproduce it.

You can expect an acknowledgement within 7 days. We aim to fix confirmed
problems within 90 days and will credit you in the fix unless you prefer
otherwise. There is no bug bounty.

## In scope

- A crafted packet that crashes the sniffer, makes it hang or use unbounded
  memory, or causes a wrong decode that hides an attack.
- Content from captured traffic reaching the dashboard in a way that runs
  script in the viewer's browser.
- Anything that lets a remote party, or a web page you visit, read
  `logs/packets.jsonl` or any file other than `dashboard.html` and
  `www/alerts.json` through `serve.py`, or read those two from another
  origin.

## Out of scope

- Evasion already listed under **Known limitations** in the README (for
  example FIN/NULL/Xmas or UDP scans, IPv6, very slow scans).
- Exposing the dashboard server on a public interface yourself, or putting
  a proxy in front of it without access control.

## Responsible use

NetSnare captures every packet on the interface it watches, and
`logs/packets.jsonl` stores the decoded headers. Run it only on machines and
networks you own or are explicitly authorised to monitor, and treat its
output files as sensitive.
