import asyncio
from dataclasses import dataclass
import socket
import time
from dns.asyncresolver import Resolver
from dns.resolver import NXDOMAIN, NoAnswer

_DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


async def resolve_hostname(hostname: str, family: int = socket.AF_INET) -> str:
    """Resolve hostname to IP. Tries system resolver first, then dnspython with public DNS."""
    try:
        loop = asyncio.get_running_loop()
        return (await loop.getaddrinfo(hostname, None, family=family))[0][4][0]
    except Exception:
        pass
    resolver = Resolver()
    resolver.nameservers = _DNS_NAMESERVERS
    resolver.timeout = 5
    resolver.lifetime = 5
    answers = await resolver.resolve(hostname, "A" if family == socket.AF_INET else "AAAA")
    return answers[0].to_text()

@dataclass
class DNSResult:
    target: str
    record_type: str
    records: list[dict]
    query_time_ms: float
    error: str | None

async def dns_lookup(target: str, record_type: str = "ALL") -> DNSResult:
    resolver = Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    start_time = time.perf_counter()
    records_out = []
    error = None
    
    types_to_query = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"] if record_type == "ALL" else [record_type]

    async def query_type(qtype: str):
        try:
            answers = await resolver.resolve(target, qtype)
            for rdata in answers:
                rec = {"type": qtype, "ttl": answers.rrset.ttl}
                if qtype in ["A", "AAAA", "CNAME", "NS"]:
                    rec["value"] = rdata.to_text()
                elif qtype == "MX":
                    rec["value"] = rdata.exchange.to_text()
                    rec["priority"] = rdata.preference
                elif qtype == "TXT":
                    rec["value"] = str(rdata.to_text())
                elif qtype == "SOA":
                    rec["value"] = rdata.mname.to_text()
                    rec["mname"] = rdata.mname.to_text()
                    rec["rname"] = rdata.rname.to_text()
                    rec["serial"] = rdata.serial
                else:
                    rec["value"] = rdata.to_text()
                records_out.append(rec)
        except NXDOMAIN:
            return "Domain not found"
        except NoAnswer:
            return "No records of this type"
        except Exception as e:
            if "timeout" in str(e).lower():
                return "Query timed out"
            return str(e)

    tasks = [query_type(t) for t in types_to_query]
    results = await asyncio.gather(*tasks)
    
    query_time_ms = (time.perf_counter() - start_time) * 1000
    
    if records_out:
        error = None
    elif results:
        for res in results:
            if isinstance(res, str):
                error = res
                if error == "Domain not found":
                    break
                    
    return DNSResult(
        target=target,
        record_type=record_type,
        records=records_out,
        query_time_ms=query_time_ms,
        error=error
    )
