from vedavaapi.common.api_common import get_repo

from .. import VedavaapiUllekhanam


def myservice():
    return VedavaapiUllekhanam.instance


# methods acessing db
def get_colln():
    repo_name = get_repo()
    return myservice().colln(repo_name)


def resource_dir_path(resource_id):
    repo_name = get_repo()
    return myservice().resource_dir_path(repo_name, resource_id)


def resource_file_path(resource_id, file_path_in_resource_scope):
    repo_name = get_repo()
    return myservice().resource_file_path(repo_name, resource_id, file_path_in_resource_scope)


# importing blueprints
from .v1 import api_blueprint_v1
