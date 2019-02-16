import os
from collections import namedtuple

import requests
from flask import g
from requests import HTTPError

from vedavaapi.common.api_common import get_current_org

from . import myservice


def _get_objstore_colln():
    org_name = get_current_org()
    return myservice().colln(org_name)


def _get_token_resolver_endpoint():
    current_org_name = get_current_org()
    accounts_api_config = myservice().get_accounts_api_config(current_org_name)

    url_root = accounts_api_config.get('url_root', g.original_url_root)
    token_resolver_endpoint = os.path.join(
        url_root.lstrip('/'),
        current_org_name,
        'accounts/oauth/v1/resolve_token'
    )
    return token_resolver_endpoint


def _get_initial_agents():
    current_org_name = get_current_org()
    initial_agents = myservice().get_initial_agents(current_org_name)
    if initial_agents is not None:
        return initial_agents

    accounts_api_config = myservice().get_accounts_api_config(current_org_name)
    url_root = accounts_api_config.get('url_root', g.original_url_root)
    initial_agents_endpoint = os.path.join(
        url_root.lstrip('/'),
        current_org_name,
        'accounts/agents/v1/initial_agents'
    )

    response = requests.get(initial_agents_endpoint)
    try:
        response.raise_for_status()
    except HTTPError:
        return None
    initial_agents_json = response.json()

    InitialAgents = namedtuple('InitialAgents', ['all_users_group_id', 'root_admin_id', 'root_admins_group_id'])
    initial_agents = InitialAgents(
        initial_agents_json.get('all_users_group_id', None),
        initial_agents_json.get('root_admin_id', None), initial_agents_json.get('root_admins_group_id', None))
    myservice().set_initial_agents(current_org_name, initial_agents)

    return initial_agents


def push_environ_to_g():
    g.token_resolver_endpoint = _get_token_resolver_endpoint()
    g.current_org_name = get_current_org()
    g.objstore_colln = _get_objstore_colln()
    g.initial_agents = _get_initial_agents()
