import json
import urllib.parse
import urllib.request


def GetSubDomain(domain, token):
    _dict = {}
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': domain, 'apikey': token}
    try:
        response = urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()
        _dict = json.loads(response)
    except Exception as exception:
        raise exception
    return _dict["subdomains"]


