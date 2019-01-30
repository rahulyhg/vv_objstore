from collections import namedtuple

from sanskrit_ld.schema.base import ObjectPermissions
from sanskrit_ld.schema.books import Library
from vedavaapi.common.api_common import get_initial_agents

from vedavaapi.objectdb.objstore_helper import get_resource, set_default_permissions


InitialResources = namedtuple('InitialResources', ['genesis_resource_id'])


# noinspection PyProtectedMember
def bootstrap_initial_resources(colln, org_name, org_config):
    org_genesis_resource = get_resource(colln, _id='0', projection={"_id": 1, "name": 1})
    if org_genesis_resource is not None:
        return InitialResources(org_genesis_resource._id)

    initial_agents = get_initial_agents()

    org_genesis_resource = Library()
    org_genesis_resource._id = '0'
    org_genesis_resource.creator = initial_agents.root_admin_id
    org_genesis_resource.set_details(name='{} library'.format(org_name))
    org_genesis_resource.source = None

    org_genesis_resource.permissions = ObjectPermissions.template_object_permissions()

    org_genesis_resource.permissions.add_to_granted_list(
        [ObjectPermissions.READ, ObjectPermissions.LIST, ObjectPermissions.LINK_FROM_OTHERS],
        group_pids=[initial_agents.all_users_group_id])
    org_genesis_resource.permissions.add_to_granted_list(
        [ObjectPermissions.UPDATE_CONTENT], user_pids=[initial_agents.root_admin_id], group_pids=[initial_agents.root_admins_group_id])

    inserted_id = colln.insert_one(org_genesis_resource.to_json_map())
    return InitialResources(inserted_id)
