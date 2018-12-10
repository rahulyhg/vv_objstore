import os
import shutil

import sanskrit_ld.helpers.db_helper as db_helper
from sanskrit_ld.helpers.db_helper import PermissionManager
from sanskrit_ld.schema import JsonObject
from sanskrit_ld.schema.base import Resource, FileDescriptor
from sanskrit_ld.schema.base.annotations import FileAnnotation
from sanskrit_ld.schema.users import User, Permission
from werkzeug.utils import secure_filename

from . import resource_file_path, resource_dir_path


class UllekhanamPermissionManager(PermissionManager):

    def has_persmission(self, user, action, obj=None):
        """

        :param obj:
        :param action:
        :type user: User
        :return:
        """
        return user.check_permission('ullekhanam', action)


permission_manager = UllekhanamPermissionManager()


def raise_if_overwrites(obj, increment, attributes):
    """

    :type obj: object
    :type increment: object
    :param attributes:
    :return:
    """
    for attr in attributes:
        if not (hasattr(obj, attr) and hasattr(increment, attr)):
            continue
        if obj.__getattribute__(attr) != increment.__getattribute__(attr):
            raise PermissionError("cannot override '{}' property".format(attr))


def delete_attributes(obj, attributes):
    for attr in attributes:
        if hasattr(obj, attr):
            value = obj.__getattribute__(attr)
            del value


# noinspection PyProtectedMember
def handle_creation_details(colln, user, resource):
    if not isinstance(resource, Resource):
        return resource
    user_id = user.authentication_infos[0].user_id

    if hasattr(resource, '_id'):
        old_object = JsonObject.make_from_dict(db_helper.read_by_id(colln, resource._id))
        raise_if_overwrites(old_object, resource, ["creator", "created"])
        # TODO modified time to be setted, contributors to be updated.
    else:
        resource.creator = user_id
        resource.contributor = [user_id]
        delete_attributes(resource, ["created"])
        resource.update_time()

    return resource


def get_associated_resource_ids(colln, resource_id, request_doc):
    associated_res_ids = {}
    if 'files' in request_doc:
        files_request = request_doc['files']
        if isinstance(files_request, bool) and files_request:
            files_filter_doc = {}
        else:
            files_filter_doc = files_request
        file_annos = db_helper.files(
            colln, resource_id, filter_doc=files_filter_doc, fields=['_id'], return_generator=True)
        file_anno_ids = [anno['_id'] for anno in file_annos]
        associated_res_ids['files'] = file_anno_ids

    if 'specific_resources' in request_doc:
        sprs_request = request_doc['specific_resources']
        if isinstance(sprs_request, bool) and sprs_request:
            sprs_filter_doc = {}
        else:
            sprs_filter_doc = sprs_request
        sprs = db_helper.specific_resources(
            colln, resource_id, filter_doc=sprs_filter_doc, fields=['_id'], return_generator=True)
        spr_ids = [spr['_id'] for spr in sprs]
        associated_res_ids['specific_resources'] = spr_ids

    if 'annotations' in request_doc:
        annos_request = request_doc['annotations']
        if isinstance(annos_request, bool) and annos_request:
            annos_filter_doc = {}
        else:
            annos_filter_doc = annos_request
        annos = db_helper.annotations(
            colln, resource_id, filter_doc=annos_filter_doc, fields=['_id'], return_generator=True)
        anno_ids = [anno['_id'] for anno in annos]
        associated_res_ids['annotations'] = anno_ids
    return associated_res_ids


def attach_associated_resources(colln, resource_reprs, associated_resources_request_doc):
    for resource in resource_reprs:
        associated_resource_ids = get_associated_resource_ids(
            colln, resource['_id'], associated_resources_request_doc
        )
        resource['associated_resources'] = associated_resource_ids


def save_file(colln, user, resource_id, file, purpose):
    file_name = secure_filename(os.path.basename(file.filename))
    file_path = resource_file_path(resource_id, file_name)

    file_descriptor = FileDescriptor.from_details(file_name)
    file_annotation = FileAnnotation.from_details(file_descriptor, resource_id, purpose=purpose)
    handle_creation_details(colln, user, file_annotation)
    file_annotation.validate()
    created_doc = db_helper.update(colln, file_annotation, user, permission_manager)
    created_anno = JsonObject.make_from_dict(created_doc)

    file.save(file_path)
    return created_anno


def delete_resource_dir(resource_id):
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
        file_anno = JsonObject.make_from_dict(db_helper.read_by_id(colln, file_anno_or_id))  # type: FileAnnotation

    target_resource_id = file_anno.target
    target_resource = JsonObject.make_from_dict(db_helper.read_by_id(colln, target_resource_id))

    has_update_permission = permission_manager.has_persmission(user, Permission.UPDATE, obj=target_resource)

    if not has_update_permission:
        raise PermissionError('no permission to update resource and it\'s files')

    # noinspection PyProtectedMember
    colln.delete_item(file_anno._id)
    file_path_in_resource_scope = file_anno.body.path
    file_path = resource_file_path(target_resource_id, file_path_in_resource_scope)
    os.remove(file_path)


class TreeCrawlError(Exception):
    def __init__(self, msg, tree_position, node_json, error):
        super(TreeCrawlError, self).__init__(msg)
        self.tree_position = tree_position
        self.node_json = node_json
        self.error = error


def update_tree(colln, user, branch, branch_path, parent_id, branch_root_node_type='root'):
    result_branch = {}

    root_node_content = branch['content']
    root_node = JsonObject.make_from_dict(root_node_content)
    handle_creation_details(colln, user, root_node)

    if branch_root_node_type == 'annotation':
        root_node.target = parent_id
    elif branch_root_node_type == 'section':
        root_node.source = parent_id

    try:
        root_node.validate()
        root_node_json = db_helper.update(colln, root_node, user, permission_manager=permission_manager)
        result_branch['content'] = root_node_json
    except Exception as e:
        raise TreeCrawlError(
            'content is invalid', tree_position=branch_path, node_json=root_node.to_json_map(), error=str(e)
        )

    annotation_sub_branches = branch.get('annotations', [])
    result_annotation_sub_branches = []
    for n, sb in enumerate(annotation_sub_branches):
        sub_branch_path = branch_path+'.annotations[0]'
        result_annotation_sub_branch = update_tree(
            colln, user, sb, sub_branch_path, root_node_json['_id'], branch_root_node_type='annotation')
        result_annotation_sub_branches.append(result_annotation_sub_branch)

    if len(annotation_sub_branches):
        result_branch['annotations'] = result_annotation_sub_branches

    section_sub_branches = branch.get('sections', [])
    result_section_sub_branches = []
    for n, sb in enumerate(section_sub_branches):
        sub_branch_path = branch_path+'.sections[0]'
        result_section_sub_branch = update_tree(
            colln, user, sb, sub_branch_path, root_node_json['_id'], branch_root_node_type='section')
        result_section_sub_branches.append(result_section_sub_branch)

    if len(section_sub_branches):
        result_branch['sections'] = result_section_sub_branches

    return result_branch


def read_tree(
        colln, root_node, max_depth,
        specific_resource_filter=None, annotation_filter=None,
        specific_resource_fields=None, annotation_fields=None):
    tree = {
        "content": root_node
    }
    if specific_resource_fields is not None and '_id' not in specific_resource_fields:
        specific_resource_fields.append('_id')

    specific_resources = db_helper.specific_resources(
        colln, root_node['_id'], filter_doc=specific_resource_filter, fields=specific_resource_fields)

    specific_resource_sub_branches = []
    for spr in specific_resources:
        sub_branch = read_tree(
            colln, spr, max_depth-1,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_fields=specific_resource_fields,
            annotation_fields=annotation_fields
        )
        specific_resource_sub_branches.append(sub_branch)

    if annotation_fields is not None and '_id' not in annotation_fields:
        annotation_fields.append('_id')

    annotations = db_helper.annotations(
        colln, root_node['_id'], filter_doc=annotation_filter, fields=annotation_fields)

    annotation_sub_branches = []
    for anno in annotations:
        sub_branch = read_tree(
            colln, anno, max_depth-1,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_fields=specific_resource_fields,
            annotation_fields=annotation_fields
        )
        annotation_sub_branches.append(sub_branch)

    tree['sections'] = specific_resource_sub_branches
    tree['annotations'] = annotation_sub_branches
    return tree
