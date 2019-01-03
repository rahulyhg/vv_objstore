import os
import shutil
import sys

from sanskrit_ld.helpers import db_helper
from sanskrit_ld.helpers.permissions_helper import PermissionResolver
from sanskrit_ld.schema import JsonObject
from sanskrit_ld.schema.base import FileDescriptor, ObjectPermissions
from sanskrit_ld.schema.base.annotations import FileAnnotation
from vedavaapi.common.api_common import get_initial_agents
from vedavaapi.objectdb.mydb import MyDbCollection
from werkzeug.utils import secure_filename


def resource_selector_doc(resource_id):
    return {"_id": resource_id}


def get_resource_json(colln, _id, projection=None):
    return colln.get(_id, projection=projection)


def modified_projection(projection, mandatory_attrs=None):
    mandatory_attrs = mandatory_attrs or []
    if projection is None:
        return None
    projection = projection.copy()

    for attr in mandatory_attrs:
        if 0 in projection.values():
            projection.pop(attr, 0)
        elif 1 in projection.values():
            projection[attr] = 1

    return projection


def delete_if_not_requested(doc, attrs, projection):
    if projection is None:
        return

    if 0 in projection.values():
        for attr in attrs:
            if attr in projection:
                delattr(doc, attr)

    elif 1 in projection.values():
        for attr in attrs:
            if attr not in projection:
                delattr(doc, attr)


def get_resource(colln, _id, projection=None):
    projection = modified_projection(projection, ['jsonClass'])

    resource_json = colln.find_one({"_id": _id}, projection=projection)
    return JsonObject.make_from_dict(resource_json)


def delete_attributes(obj, attributes):
    for attr in attributes:
        if hasattr(obj, attr):
            value = obj.__getattribute__(attr)
            del value


def get_source_or_target_id(resource):
    if hasattr(resource, 'source'):
        return resource.source
    elif hasattr(resource, 'target'):
        return resource.target
    return None


def validate_insertion(colln, resource, user):
    white_listed_classes = ('JsonObject', 'WrapperObject', 'FileAnnotation')
    not_allowed_attributes = ['creator', 'created', 'permissions']
    for attr in not_allowed_attributes:
        if hasattr(resource, attr):
            raise ValueError(attr + " attribute cannot be setted through this api")

    if resource.json_class in white_listed_classes:
        raise TypeError('object type not supported')

    source_or_target_id = get_source_or_target_id(resource)
    if not source_or_target_id:
        raise ValueError('resource cannot be orphan')

    source_or_target = get_resource(
        colln, source_or_target_id, projection={"permissions": 1, "target": 1, "source": 1, "_id": 1, "jsonClass": 1})
    if not PermissionResolver.resolve_permission(source_or_target, ObjectPermissions.LINK_FROM_OTHERS, user, colln):
        raise PermissionError('permission denied. has no permission to link to target/source')


# noinspection PyProtectedMember
def validate_update(colln, resource, user):

    old_resource = get_resource(colln, resource._id)
    if old_resource is None:
        raise ValueError('resource does not exists')

    not_allowed_attributes = ['creator', 'created', 'permissions', 'source', 'target']
    for attr in not_allowed_attributes:
        if hasattr(resource, attr):
            if hasattr(old_resource, attr) and getattr(old_resource, attr) == getattr(resource, attr):
                continue
            raise ValueError(attr + " attribute cannot be setted through this api")

    if not PermissionResolver.resolve_permission(old_resource, ObjectPermissions.UPDATE_CONTENT, user, colln):
        raise PermissionError('permission denied')


# noinspection PyProtectedMember
def create_or_update(colln, resource, user, validate_operation=True, return_doc_projection=None):
    """

    :param return_doc_projection:
    :param validate_operation:
    :type colln: MyDbCollection
    :type resource: JsonObject
    :param user:
    :return:
    """
    if hasattr(resource, '_id'):
        validate_update(colln, resource, user)
        resource.update_time(just_update=True)
        resource.validate(diff=True)
        colln.update_one({"_id": resource._id}, {"$set": resource.to_json_map()})
        return get_resource_json(colln, resource._id, projection=return_doc_projection)
    else:
        if validate_operation:
            validate_insertion(colln, resource, user)
        resource.update_time()
        resource.creator = user._id
        set_default_permissions(resource, user._id)
        resource.validate()
        inserted_id = colln.insert_one(resource.to_json_map()).inserted_id
        return get_resource_json(colln, inserted_id, projection=return_doc_projection)


# noinspection PyProtectedMember
def set_default_permissions(resource, creator_id):
    resource.permissions = ObjectPermissions.template_object_permissions()
    initial_agents = get_initial_agents()
    resource.permissions.add_to_granted_list(
        ObjectPermissions.ACTIONS, user_pids=[creator_id], group_pids=[initial_agents.root_admins_group_id])
    resource.permissions.add_to_granted_list(
        [ObjectPermissions.READ, ObjectPermissions.LIST], group_pids=[initial_agents.all_users_group_id])


def get_associated_resource_ids(colln, resource_id, request_doc):
    associated_res_ids = {}
    if 'files' in request_doc:
        files_request = request_doc['files']
        if isinstance(files_request, bool) and files_request:
            files_filter_doc = {}
        else:
            files_filter_doc = files_request
        file_annos = db_helper.files(
            colln, resource_id, filter_doc=files_filter_doc, projection={"_id": 1}, return_generator=True)
        file_anno_ids = [anno['_id'] for anno in file_annos]
        associated_res_ids['files'] = file_anno_ids

    if 'specific_resources' in request_doc:
        sprs_request = request_doc['specific_resources']
        if isinstance(sprs_request, bool) and sprs_request:
            sprs_filter_doc = {}
        else:
            sprs_filter_doc = sprs_request
        sprs = db_helper.specific_resources(
            colln, resource_id, filter_doc=sprs_filter_doc, projection={"_id": 1}, return_generator=True)
        spr_ids = [spr['_id'] for spr in sprs]
        associated_res_ids['specific_resources'] = spr_ids

    if 'annotations' in request_doc:
        annos_request = request_doc['annotations']
        if isinstance(annos_request, bool) and annos_request:
            annos_filter_doc = {}
        else:
            annos_filter_doc = annos_request
        annos = db_helper.annotations(
            colln, resource_id, filter_doc=annos_filter_doc, projection={"_id": 1}, return_generator=True)
        anno_ids = [anno['_id'] for anno in annos]
        associated_res_ids['annotations'] = anno_ids
    return associated_res_ids


def attach_associated_resources(colln, resource_reprs, associated_resources_request_doc):
    for resource in resource_reprs:
        associated_resource_ids = get_associated_resource_ids(
            colln, resource['_id'], associated_resources_request_doc
        )
        resource['associated_resources'] = associated_resource_ids


# noinspection PyProtectedMember
def save_file(colln, user, resource_id, file, purpose):
    #  requires request context
    from vedavaapi.objstore.api import resource_file_path
    file_name = secure_filename(os.path.basename(file.filename))
    file_path = resource_file_path(resource_id, file_name)

    file_descriptor = FileDescriptor.from_details(path=file_name)
    file_annotation = FileAnnotation.from_details(file=file_descriptor, target=resource_id, purpose=purpose)
    print(file_annotation.to_json_map())

    created_doc = create_or_update(colln, file_annotation, user, validate_operation=False)
    created_anno = JsonObject.make_from_dict(created_doc)

    file.save(file_path)
    return created_anno


def delete_resource_dir(resource_id):
    # requires request context
    from ..api import resource_dir_path
    res_dir_path = resource_dir_path(resource_id)
    if os.path.exists(res_dir_path):
        shutil.rmtree(res_dir_path)


# noinspection PyUnresolvedReferences
def delete_resource_file(colln, user, file_anno_or_id):
    """

    :type colln: MyDbCollection
    :param user:
    :param file_anno_or_id:
    :return:
    """
    if isinstance(file_anno_or_id, FileAnnotation):
        file_anno = file_anno_or_id  # type: FileAnnotation
    else:
        file_anno = JsonObject.make_from_dict(colln.get(file_anno_or_id))  # type: FileAnnotation

    if file_anno is None:
        raise ValueError('resource not found')

    if not PermissionResolver.resolve_permission(file_anno, ObjectPermissions.DELETE, user, colln):
        raise PermissionError('permission denied')

    # noinspection PyProtectedMember
    colln.delete_item(file_anno._id)
    from ..api import resource_file_path
    file_path_in_resource_scope = file_anno.body.path
    file_path = resource_file_path(target_resource_id, file_path_in_resource_scope)
    os.remove(file_path)


class TreeValidationError(Exception):
    def __init__(self, msg, invalid_node_path, invalid_node_json, error, parent_node_id):
        super(TreeValidationError, self).__init__(msg)
        self.invalid_node_path = invalid_node_path
        self.invalid_node_json = invalid_node_json
        self.error = error
        self.parent_node_id = parent_node_id


def update_tree(
        colln, user, branch, branch_path, parent_id, branch_root_node_type='root',
        root_node_projection=None, specific_resource_projection=None, annotation_projection=None):
    result_branch = {}

    branch_root_node_content = branch['content']
    branch_root_node = JsonObject.make_from_dict(branch_root_node_content)

    if branch_root_node_type == 'annotation':
        branch_root_node.target = parent_id
        projection = annotation_projection
    elif branch_root_node_type == 'section':
        branch_root_node.source = parent_id
        projection = specific_resource_projection
    else:
        projection = root_node_projection

    try:
        branch_root_node_json = create_or_update(colln, branch_root_node, user, return_doc_projection=projection)

        result_branch['content'] = branch_root_node_json

    except Exception as e:
        raise TreeValidationError(
            'some node in tree is invalid.',
            invalid_node_path=branch_path,
            invalid_node_json=branch_root_node.to_json_map(),
            error=str(e),
            parent_node_id=parent_id
        )

    annotation_sub_branches = branch.get('annotations', [])
    result_annotation_sub_branches = []
    for n, sb in enumerate(annotation_sub_branches):
        sub_branch_path = branch_path+'.annotations[0]'
        result_annotation_sub_branch = update_tree(
            colln, user, sb, sub_branch_path, branch_root_node_json['_id'], branch_root_node_type='annotation',
            root_node_projection=root_node_projection,
            annotation_projection=annotation_projection,
            specific_resource_projection=specific_resource_projection)
        result_annotation_sub_branches.append(result_annotation_sub_branch)

    if len(annotation_sub_branches):
        result_branch['annotations'] = result_annotation_sub_branches

    section_sub_branches = branch.get('sections', [])
    result_section_sub_branches = []
    for n, sb in enumerate(section_sub_branches):
        sub_branch_path = branch_path+'.sections[0]'
        result_section_sub_branch = update_tree(
            colln, user, sb, sub_branch_path, branch_root_node_json['_id'], branch_root_node_type='section',
            root_node_projection=root_node_projection,
            annotation_projection=annotation_projection,
            specific_resource_projection=specific_resource_projection)
        result_section_sub_branches.append(result_section_sub_branch)

    if len(section_sub_branches):
        result_branch['sections'] = result_section_sub_branches

    return result_branch


def read_tree(
        colln, root_node, max_depth,
        specific_resource_filter=None, annotation_filter=None,
        specific_resource_projection=None, annotation_projection=None):
    tree = {
        "content": root_node
    }
    specific_resource_projection = modified_projection(specific_resource_projection, mandatory_attrs=['_id'])

    specific_resources = db_helper.specific_resources(
        colln, root_node['_id'], filter_doc=specific_resource_filter, projection=specific_resource_projection)

    specific_resource_sub_branches = []
    for spr in specific_resources:
        sub_branch = read_tree(
            colln, spr, max_depth-1,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_projection=specific_resource_projection,
            annotation_projection=annotation_projection
        )
        specific_resource_sub_branches.append(sub_branch)

    annotation_projection = modified_projection(annotation_projection, mandatory_attrs=['_id'])

    annotations = db_helper.annotations(
        colln, root_node['_id'], filter_doc=annotation_filter, projection=annotation_projection)

    annotation_sub_branches = []
    for anno in annotations:
        sub_branch = read_tree(
            colln, anno, max_depth-1,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_projection=specific_resource_projection,
            annotation_projection=annotation_projection
        )
        annotation_sub_branches.append(sub_branch)

    tree['sections'] = specific_resource_sub_branches
    tree['annotations'] = annotation_sub_branches
    return tree
