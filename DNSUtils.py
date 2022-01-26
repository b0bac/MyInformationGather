import dns.resolver


def GetARecord(domain):
    result = []
    try:
        for answer in dns.resolver.resolve(domain, "A").response.answer:
            for item in answer.items:
                if item.rdtype == 1:
                    result.append(item.address)
        return result
    except Exception as exception:
        raise exception


def GetCNameRecord(domain):
    result = []
    try:
        for answer in dns.resolver.resolve(domain, "CNAME").response.answer:
            for item in answer:
                cname = str(item.to_text())
                if cname[-1] == ".":
                    cname = cname[0:-1]
                result.append(cname)
        return result
    except Exception as exception:
        raise exception
