import dns.resolver

def dns_lookup(domain):
    dns_result = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_result[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            dns_result[rtype] = []
    return dns_result
