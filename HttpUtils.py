import re
import requests


def HttpGet(url):
    message = ""
    try:
        response = requests.get(url, timeout=3)
    except Exception as exception:
        message = exception
        return None, message
    if response.status_code == 200:
        return response, message
    else:
        return None, message


def HttpsGet(url):
    message = ""
    try:
        response = requests.get(url, verify=False, timeout=3)
    except Exception as exception:
        message = exception
        return None, message
    if response.status_code == 200:
        return response, message
    else:
        return None, message


def WebPageTitle(response):
    content = str(response.text)
    title = re.findall('<title>(.+)</title>', content)
    return title[0]


def HttpScan(ip, port):
    response = None
    message = None
    url = "http://%s:%s" % (str(ip), str(port))
    response, message = HttpGet(url)
    if response is not None:
            return WebPageTitle(response), message
    url = "https://%s:%s" % (str(ip), str(port))
    response, message = HttpsGet(url)
    if response is not None:
        return WebPageTitle(response), message
    else:
        return None, message

