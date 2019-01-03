from collections import namedtuple

from sanskrit_ld.schema.books import Library
from vedavaapi.common.api_common import get_initial_agents

from .resources_helper import get_resource, set_default_permissions


InitialResources = namedtuple('InitialResources', ['root_library_id'])


# noinspection PyProtectedMember
def bootstrap_initial_resources(colln):
    print('in bootstrap resources')
    root_library = get_resource(colln, _id='0', projection={"_id": 1, "name": 1})
    if root_library is not None:
        print(root_library.to_json_map())
        return InitialResources(root_library._id)

    initial_agents = get_initial_agents()

    root_library = Library()
    root_library._id = '0'
    root_library.creator = initial_agents.root_admin_id
    root_library.set_details(name='All Books')

    set_default_permissions(root_library, initial_agents.root_admin_id)

    inserted_id = colln.insert_one(root_library.to_json_map())
    return InitialResources(inserted_id)
