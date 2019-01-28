from vedavaapi.common.api_common import get_current_org
from vedavaapi.objectdb.mydb import MyDbCollection

from .. import VedavaapiObjstore


def myservice():
    return VedavaapiObjstore.instance


def get_colln():
    org_name = get_current_org()
    colln = myservice().colln(org_name)  # type: MyDbCollection
    return colln


def resource_dir_path(resource_id):
    org_name = get_current_org()
    return myservice().resource_dir_path(org_name, resource_id)


def resource_file_path(resource_id, file_path_in_resource_scope):
    org_name = get_current_org()
    return myservice().resource_file_path(org_name, resource_id, file_path_in_resource_scope)


# importing blueprints
from .v1 import api_blueprint_v1

blueprints_path_map = {
    api_blueprint_v1: "/v1"
}
