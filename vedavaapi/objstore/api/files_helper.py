import os
import shutil
from werkzeug.utils import secure_filename

from sanskrit_ld.helpers.permissions_helper import PermissionResolver
from sanskrit_ld.schema import JsonObject
from sanskrit_ld.schema.base import FileDescriptor, ObjectPermissions
from sanskrit_ld.schema.base.annotations import FileAnnotation
from vedavaapi.objectdb.helpers import objstore_helper

from . import resource_file_path, resource_dir_path


# noinspection PyProtectedMember
def save_file(colln, user_id, user_group_ids, resource_id, file, purpose, initial_agents=None):
    file_name = secure_filename(os.path.basename(file.filename))
    file_path = resource_file_path(resource_id, file_name)

    file_descriptor = FileDescriptor.from_details(path=file_name)
    file_annotation = FileAnnotation.from_details(file=file_descriptor, target=resource_id, purpose=purpose)

    created_doc_id = objstore_helper.create_or_update(
        colln, file_annotation.to_json_map(), user_id, user_group_ids, validate_operation=False, initial_agents=initial_agents)
    created_doc_json = colln.get(created_doc_id)
    created_anno = JsonObject.make_from_dict(created_doc_json)

    file.save(file_path)
    return created_anno


def delete_resource_dir(resource_id):
    res_dir_path = resource_dir_path(resource_id)
    if os.path.exists(res_dir_path):
        shutil.rmtree(res_dir_path)


def delete_resource_file(colln, user_id, user_group_ids, file_anno_or_id):
    if isinstance(file_anno_or_id, FileAnnotation):
        file_anno = file_anno_or_id  # type: FileAnnotation
    else:
        file_anno = JsonObject.make_from_dict(colln.get(file_anno_or_id))  # type: FileAnnotation

    if file_anno is None:
        raise ValueError('resource not found')

    if not PermissionResolver.resolve_permission(file_anno, ObjectPermissions.DELETE, user_id, user_group_ids, colln):
        raise PermissionError('permission denied')

    # noinspection PyProtectedMember
    colln.delete_item(file_anno._id)
    file_path_in_resource_scope = file_anno.body.path
    file_path = resource_file_path(file_anno.target, file_path_in_resource_scope)
    os.remove(file_path)
