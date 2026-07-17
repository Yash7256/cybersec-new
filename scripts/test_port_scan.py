#!/usr/bin/env python3
"""
Run a port scan on localhost:80 and print CVE results from port_scanner directly.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybersec.core.tools.port_scanner import scan_ports


async def main():
    result = await scan_ports("localhost", ports=[80], allow_private=True)

    print(f"Target: {result.target}")
    print(f"Open ports: {result.open_ports_count}")
    print()

    for p in result.open_ports:
        cves = []
        if p.cve_result and p.cve_result.cves:
            for cve in p.cve_result.cves[:10]:  # show top 10
                cves.append({
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "description": (cve.description or "")[:150],
                })

        entry = {
            "port": p.port_number,
            "service": p.service,
            "version": p.version,
            "banner": p.raw_banner,
            "cve_count": p.cve_count,
            "cve_critical": p.cve_critical_count,
            "cve_high": p.cve_high_count,
            "cve_medium": p.cve_medium_count,
            "cve_low": p.cve_low_count,
            "max_cvss_score": p.max_cvss_score,
            "max_cvss_severity": p.max_cvss_severity,
            "max_cvss_cve": p.max_cvss_cve,
            "top_cves": cves,
        }
        print(json.dumps(entry, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
