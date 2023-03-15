"""Formatters.py ."""
import requests

from constants.general import (
    PROXY_PASSWORD,
    PROXY_PORT,
    PROXY_TYPE_HTTP,
    PROXY_TYPE_HTTPS,
    PROXY_URL,
    PROXY_USERNAME,
    STR_COLON,
)


def format_proxy_uri(proxy_dict):
    """
    Get Function to get proxy uri in format of.

    <protocol>://<user_name>:<password>@<proxy_server_ip>:<proxy_port>

    :param proxy_dict: dict, Dictionary containing proxy information
    :return: proxy_uri: str, proxy uri in standard format
    """
    uname = requests.compat.quote_plus(proxy_dict.get(PROXY_USERNAME, ""))
    passwd = requests.compat.quote_plus(proxy_dict.get(PROXY_PASSWORD, ""))
    proxy_url = proxy_dict.get(PROXY_URL)
    proxy_port = proxy_dict.get(PROXY_PORT)
    if uname and passwd:
        proxy_uri = f"{PROXY_TYPE_HTTP}://{uname}:{passwd}@{proxy_url}:{proxy_port}"
    else:
        proxy_uri = f"{proxy_url}{STR_COLON}{proxy_port}"
    proxy_settings = {PROXY_TYPE_HTTPS: f"{proxy_uri}"}
    return proxy_settings
