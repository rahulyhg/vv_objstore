import json
import os
from collections import OrderedDict

import flask_restplus
from flask import request
from jsonschema import ValidationError
from werkzeug.datastructures import FileStorage

from sanskrit_ld.helpers.permissions_helper import PermissionResolver
from sanskrit_ld.schema import JsonObject
from sanskrit_ld.schema.base import ObjectPermissions, Permission

from vedavaapi.common.api_common import jsonify_argument, error_response, check_argument_type, \
    abort_with_error_response, get_current_org, get_user, get_group
from vedavaapi.common.api_common import get_current_user_id, get_current_user_group_ids, get_initial_agents
from vedavaapi.objectdb import objstore_helper as objstore_helper

from . import api
from .. import get_colln, resource_file_path
from ..files_helper import save_file, delete_resource_file, delete_resource_dir


def _validate_projection(projection):
    try:
        objstore_helper.validate_projection(projection)
    except objstore_helper.ObjModelException as e:
        error = error_response(message=e.message, code=e.http_response_code)
        abort_with_error_response(error)


def get_requested_resources(args):
    colln = get_colln()
    current_user_id = get_current_user_id(required=False)
    current_user_group_ids = get_current_user_group_ids()

    selector_doc = jsonify_argument(args.get('selector_doc', None), key='selector_doc') or {}
    check_argument_type(selector_doc, (dict,), key='selector_doc')

    projection = jsonify_argument(args.get('projection', None), key='projection')
    check_argument_type(projection, (dict,), key='projection', allow_none=True)
    _validate_projection(projection)
    projection = objstore_helper.modified_projection(projection, mandatory_attrs=["_id", "jsonClass"])

    lrs_request_doc = jsonify_argument(args.get('linked_resources', None), 'linked_resources')
    check_argument_type(lrs_request_doc, (dict,), key='linked_resources', allow_none=True)

    sort_doc = jsonify_argument(args.get('sort_doc', None), key='sort_doc')
    check_argument_type(sort_doc, (dict, list), key='sort_doc', allow_none=True)

    ops = OrderedDict()
    if sort_doc is not None:
        ops['sort'] = [sort_doc]
    if args.get('start', None) is not None and args.get('count', None) is not None:
        ops['skip'] = [args['start']]
        ops['limit'] = [args['count']]

    try:
        resource_repr_jsons = objstore_helper.get_read_permitted_resource_jsons(
            colln, current_user_id, current_user_group_ids, selector_doc, projection=projection, ops=ops)
    except (TypeError, ValueError):
        error = error_response(message='arguments to operations seems invalid', code=400)
        abort_with_error_response(error)
    except Exception as e:
        error = error_response(message='invalid arguments', code=400)
        abort_with_error_response(error)

    if lrs_request_doc is not None:
        # noinspection PyUnboundLocalVariable
        for rj in resource_repr_jsons:
            linked_resources = objstore_helper.get_linked_resource_ids(colln, rj['_id'], lrs_request_doc)
            rj['linked_resources'] = linked_resources
    return resource_repr_jsons


@api.route('/resources')
class Resources(flask_restplus.Resource):

    white_listed_classes = ('JsonObject', 'WrapperObject', 'FileAnnotation', 'User', 'UsersGroup')

    get_parser = api.parser()
    get_parser.add_argument('selector_doc', location='args', type=str, default='{}')
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('linked_resources', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str)

    post_parser = api.parser()
    post_parser.add_argument('resources_list', location='form', type=str, required=True)
    post_parser.add_argument('attachments', type=FileStorage, location='files')
    post_parser.add_argument('attachments_infos', type=str, location='form')
    post_parser.add_argument('return_projection', location='form', type=str)
    post_parser.add_argument('return_created_linked_resources', location='form', type=bool, default=True)

    delete_parser = api.parser()
    delete_parser.add_argument('resource_ids', location='form', type=str, required=True)

    @api.expect(get_parser, validate=True)
    def get(self):
        args = self.get_parser.parse_args()
        return get_requested_resources(args)

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        resource_jsons = jsonify_argument(args['resources_list'], key='resources_list')
        check_argument_type(resource_jsons, (list, ), key='resources_list')

        attachments_infos = jsonify_argument(args['attachments_infos'], key='attachments_infos')
        check_argument_type(attachments_infos, (list, ), key='attachments_infos', allow_none=True)
        if attachments_infos is not None and len(attachments_infos) != len(resource_jsons):
            return error_response(
                message='attachments_infos should have one-to-one correspondence with resources', code=403
            )

        files = request.files.getlist("attachments")
        files_index = dict((f.filename, f) for f in files)

        return_projection = jsonify_argument(args.get('return_projection', None), key='return_projection')
        check_argument_type(return_projection, (dict,), key='return_projection', allow_none=True)
        _validate_projection(return_projection)

        return_created_lrs = args.get('return_created_linked_resources', True)

        initial_agents = get_initial_agents()
        created_resource_jsons = []
        for n, rj in enumerate(resource_jsons):
            try:
                if 'jsonClass' not in rj:
                    raise objstore_helper.ObjModelException('jsonClass attribute should exist for update/creation', 403)

                resource = JsonObject.make_from_dict(rj)
                created_resource_id = objstore_helper.create_or_update(
                    colln, resource, current_user_id, current_user_group_ids, initial_agents=initial_agents)
                if created_resource_id is None:
                    created_resource_jsons.append(None)
                    continue
                created_resource_json = colln.get(
                    created_resource_id,
                    projection=objstore_helper.modified_projection(return_projection, ["_id", "jsonClass"]))
                created_resource_jsons.append(created_resource_json)

                if not attachments_infos:
                    continue
                resource_attachments_info = attachments_infos[n]
                if not isinstance(resource_attachments_info, list):
                    return error_response(
                        message='attachments_info corresponding to each resource should be list', code=400)

                created_linked_resource_ids = {"files": []}
                for attachment_details in resource_attachments_info:
                    if not isinstance(attachment_details, dict) or (
                            'file_name' not in attachment_details or 'purpose' not in attachment_details):
                        return error_response(message='invalid attachment_details for resource {}'.format(n), code=400)

                    attachment_file_name = attachment_details['file_name']
                    attachment_purpose = attachment_details['purpose']
                    if attachment_file_name not in files_index:
                        continue
                    file_anno = save_file(
                        colln, current_user_id, current_user_group_ids, created_resource_id,
                        files_index[attachment_file_name], attachment_purpose, initial_agents=initial_agents
                    )
                    # noinspection PyProtectedMember
                    created_linked_resource_ids['files'].append(file_anno._id)

                if return_created_lrs:
                    created_resource_json['created_linked_resources'] = created_linked_resource_ids

            except objstore_helper.ObjModelException as e:
                return error_response(
                    message='action not allowed at resource {}'.format(n),
                    code=e.http_response_code, details={"error": e.message})
            except ValidationError as e:
                return error_response(
                    message='schema validation error at resource {}'.format(n),
                    code=400, details={"error": str(e)})

        return created_resource_jsons

    @api.expect(delete_parser, validate=True)
    def delete(self):
        args = self.delete_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        resource_ids = jsonify_argument(args['resource_ids'])
        check_argument_type(resource_ids, (list,))

        ids_validity = False not in [isinstance(_id, str) for _id in resource_ids]
        if not ids_validity:
            return error_response(message='ids should be strings', code=404)

        delete_report = []

        for resource_id in resource_ids:
            deleted, deleted_res_ids = objstore_helper.delete_tree(
                colln, resource_id, current_user_id, current_user_group_ids)
            for deleted_res_id in deleted_res_ids:
                delete_resource_dir(deleted_res_id)
            delete_report.append({
                "deleted": deleted,
                "deleted_resource_ids": deleted_res_ids
            })

        return delete_report


# noinspection PyMethodMayBeStatic
@api.route('/resources/<string:resource_id>')
class ResourceObject(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('linked_resources', location='args', type=str)
    get_parser.add_argument('projection', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=False)
        current_user_group_ids = get_current_user_group_ids()

        lrs_request_doc = jsonify_argument(args['linked_resources'], 'linked_resources')
        check_argument_type(lrs_request_doc, (dict,), key='associated_resources', allow_none=True)

        projection = jsonify_argument(args['projection'], 'projection')
        check_argument_type(projection, (dict,), key='projection', allow_none=True)
        _validate_projection(projection)

        resource = objstore_helper.get_resource(
            colln, resource_id, projection=objstore_helper.modified_projection(
                projection, mandatory_attrs=["jsonClass", "_id", "permissions", "target", "source"])
        )
        if not PermissionResolver.resolve_permission(
                resource, ObjectPermissions.READ, current_user_id, current_user_group_ids, colln):
            return error_response(message='permission denied', code=403)

        objstore_helper.delete_attr_if_not_requested(resource, ['permissions', 'target', 'source'], projection)
        resource_json = resource.to_json_map()

        if lrs_request_doc is not None:
            resource_json['linked_resources'] = objstore_helper.get_linked_resource_ids(
                colln, resource_id, lrs_request_doc)
        return resource_json


@api.route('/resources/<string:resource_id>/sections')
class SpecificResources(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str, default='{}')
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('linked_resources', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.specific_resources_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resources(args)

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.specific_resources_selector_doc(resource_id, custom_filter_doc=filter_doc)

        deleted_all, deleted_res_ids = objstore_helper.delete_selection(
            colln, selector_doc, current_user_id, current_user_group_ids)
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/annotations')
class Annotations(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str, default='{}')
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('linked_resources', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.annotations_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resources(args)

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.annotations_selector_doc(resource_id, custom_filter_doc=filter_doc)

        deleted_all, deleted_res_ids = objstore_helper.delete_selection(
            colln, selector_doc, current_user_id, current_user_group_ids)
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/permitted_agents')
class PermittedAgents(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('action', location='form', type=str, required=True, choices=ObjectPermissions.ACTIONS)
    post_parser.add_argument(
        'agents_set_name', location='form', type=str, required=True, choices=[Permission.GRANTED, Permission.WITHDRAWN])
    post_parser.add_argument('user_ids', location='form', type=str, default='[]')
    post_parser.add_argument('group_ids', location='form', type=str, default='[]')

    delete_parser = api.parser()
    delete_parser.add_argument('action', location='form', type=str, required=True, choices=ObjectPermissions.ACTIONS)
    delete_parser.add_argument(
        'agents_set_name', location='form', type=str, required=True, choices=[Permission.GRANTED, Permission.WITHDRAWN])
    delete_parser.add_argument('user_ids', location='form', type=str, default='[]')
    delete_parser.add_argument('group_ids', location='form', type=str, default='[]')

    @api.expect(post_parser, validate=True)
    def post(self, resource_id):
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()
        current_org_name = get_current_org()
        args = self.post_parser.parse_args()

        user_ids = jsonify_argument(args.get('user_ids', None), key='user_ids') or []
        check_argument_type(user_ids, (list, ), key='user_ids')

        group_ids = jsonify_argument(args.get('group_ids', None), key='group_ids') or []
        check_argument_type(group_ids, (list, ), key='group_ids')

        def get_user_fn(user_id, projection=None):
            return get_user(current_org_name, user_id, projection=projection)

        def get_group_fn(group_id, projection=None):
            return get_group(current_org_name, group_id, projection=projection)

        try:
            objstore_helper.add_to_permissions_agent_set(
                colln, resource_id, current_user_id, current_user_group_ids,
                args['action'], args['agents_set_name'], get_user_fn, get_group_fn,
                user_ids=user_ids, group_ids=group_ids)
        except objstore_helper.ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        resource_json = colln.get(resource_id, projection={"permissions": 1})
        resource_permissions = resource_json['permissions']
        return resource_permissions

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()
        args = self.post_parser.parse_args()

        user_ids = jsonify_argument(args.get('user_ids', None), key='user_ids') or []
        check_argument_type(user_ids, (list, ), key='user_ids')

        group_ids = jsonify_argument(args.get('group_ids', None), key='group_ids') or []
        check_argument_type(group_ids, (list, ), key='group_ids')

        try:
            objstore_helper.remove_from_permissions_agent_set(
                colln, resource_id, current_user_id, current_user_group_ids,
                args['action'], args['agents_set_name'],
                user_ids=user_ids, group_ids=group_ids)
        except objstore_helper.ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        resource_json = colln.get(resource_id, projection={"permissions": 1})
        resource_permissions = resource_json['permissions']
        return resource_permissions


@api.route('/resources/<string:resource_id>/files')
class Files(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str, default='{}')
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str)

    post_parser = api.parser()
    post_parser.add_argument('files', type=FileStorage, location='files', required=True)
    post_parser.add_argument('files_purpose', type=str, location='form')

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.files_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resources(args)

    @api.expect(post_parser, validate=True)
    def post(self, resource_id):
        args = self.post_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        initial_agents = get_initial_agents()

        files = request.files.getlist("files")
        purpose = args['files_purpose']
        file_annotation_jsons = []
        for f in files:
            file_annotation_json = save_file(
                colln, current_user_id, current_user_group_ids,
                resource_id, f, purpose, initial_agents=initial_agents).to_json_map()
            file_annotation_json.pop('body', None)
            file_annotation_jsons.append(file_annotation_json)
        return file_annotation_jsons


# noinspection PyMethodMayBeStatic
@api.route('/files/<string:file_id>')
class File(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('file', type=FileStorage, location='files')

    def get(self, file_id):
        colln = get_colln()
        current_user_id = get_current_user_id(required=False)
        current_user_group_ids = get_current_user_group_ids()

        file_anno = objstore_helper.get_resource(colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

        if not PermissionResolver.resolve_permission(
                file_anno, ObjectPermissions.READ, current_user_id, current_user_group_ids, colln):
            return error_response(message='permission denied', code=403)

        target_resource_id = file_anno.target
        abs_file_path = resource_file_path(target_resource_id, file_anno.body.path)

        file_dir = os.path.dirname(abs_file_path)
        file_name = os.path.basename(abs_file_path)
        from flask import send_from_directory
        return send_from_directory(
            directory=file_dir, filename=file_name
        )

    @api.expect(post_parser, validate=True)
    def post(self, file_id):
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        files = request.files.getlist("file")

        file_anno = objstore_helper.get_resource(colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

        target_resource_id = file_anno.target

        if not PermissionResolver.resolve_permission(
                file_anno, ObjectPermissions.UPDATE_CONTENT, current_user_id, current_user_group_ids, colln):
            return error_response(message='permission denied', code=403)

        for f in files:
            full_path = resource_file_path(target_resource_id, file_anno.body.path)
            os.remove(full_path)
            f.save(full_path)
            return {"success": True}

    def delete(self, file_id):
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        try:
            delete_resource_file(colln, current_user_id, current_user_group_ids, file_id)
        except Exception as e:
            return error_response(message=str(e), code=403)
        return {"success": True}


@api.route('/trees')
class Trees(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('trees', type=str, location='form', required=True)
    post_parser.add_argument('root_node_return_projection', location='form', type=str)
    post_parser.add_argument('sections_return_projection', location='form', type=str)
    post_parser.add_argument('annotations_return_projection', location='form', type=str)

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=True)
        current_user_group_ids = get_current_user_group_ids()

        root_node_return_projection = objstore_helper.modified_projection(
            jsonify_argument(args['root_node_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(root_node_return_projection)
        specific_resources_return_projection = objstore_helper.modified_projection(
            jsonify_argument(args['sections_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(specific_resources_return_projection)
        annotations_return_projection = objstore_helper.modified_projection(
            jsonify_argument(args['annotations_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(annotations_return_projection)

        trees = jsonify_argument(args['trees'], key='trees')
        check_argument_type(trees, (list,), key='trees')

        initial_agents = get_initial_agents()
        result_trees = []
        try:
            for i, tree in enumerate(trees):
                result_tree = objstore_helper.update_tree(
                    colln, current_user_id, current_user_group_ids, tree, 'tree{}'.format(i), None,
                    root_node_return_projection=root_node_return_projection,
                    specific_resources_return_projection=specific_resources_return_projection,
                    annotations_return_projection=annotations_return_projection,
                    initial_agents=initial_agents)
                result_trees.append(result_tree)
        except objstore_helper.TreeValidationError as e:
            return error_response(
                message="error in posting tree",
                code=400,
                invalid_node_path=e.invalid_node_path,
                invalid_node_json=e.invalid_node_json,
                error=str(e.error),
                succeded_trees=result_trees
            )
        return result_trees


@api.route('/trees/<root_node_id>')
class Tree(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('max_depth', location='args', type=int, default=1, required=True)
    get_parser.add_argument('sections_filter', location='args', type=str)
    get_parser.add_argument('annotations_filter', location='args', type=str)
    get_parser.add_argument('root_node_projection', location='args', type=str)
    get_parser.add_argument('sections_projection', location='args', type=str)
    get_parser.add_argument('annotations_projection', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, root_node_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user_id = get_current_user_id(required=False)
        current_user_group_ids = get_current_user_group_ids()

        max_depth = args['max_depth']
        specific_resources_filter = jsonify_argument(args['sections_filter']) or {}
        annotations_filter = jsonify_argument(args['annotations_filter']) or {}

        root_node_projection = objstore_helper.modified_projection(
            jsonify_argument(args['root_node_projection']), mandatory_attrs=['_id'])
        _validate_projection(root_node_projection)
        specific_resources_projection = objstore_helper.modified_projection(
            jsonify_argument(args['sections_projection']), mandatory_attrs=['_id'])
        _validate_projection(specific_resources_projection)
        annotations_projection = objstore_helper.modified_projection(
            jsonify_argument(args['annotations_projection']), mandatory_attrs=['_id'])
        _validate_projection(annotations_projection)

        try:
            tree = objstore_helper.read_tree(
                colln, root_node_id, max_depth, current_user_id, current_user_group_ids,
                specific_resources_filter=specific_resources_filter,
                annotations_filter=annotations_filter,
                root_node_projection=root_node_projection,
                specific_resources_projection=specific_resources_projection,
                annotations_projection=annotations_projection
            )
        except objstore_helper.ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        return tree


# noinspection PyMethodMayBeStatic
@api.route('/schemas')
class Schemas(flask_restplus.Resource):

    def get(self):
        from sanskrit_ld.schema import json_class_registry
        schemas = {}
        for k, v in json_class_registry.items():
            if not hasattr(v, 'schema'):
                continue
            schemas[k] = v.schema
        return schemas


# noinspection PyMethodMayBeStatic
@api.route('/schemas/<json_class>')
class Schema(flask_restplus.Resource):

    def get(self, json_class):
        from sanskrit_ld.schema import json_class_registry
        class_obj = json_class_registry.get(json_class, None)
        if class_obj is None:
            return error_response(message='{} is not defined'.format(json_class))
        return class_obj.schema


# noinspection PyMethodMayBeStatic
@api.route('/contexts/<json_class>')
class Contexts(flask_restplus.Resource):

    def get(self, json_class):
        from sanskrit_ld.schema import json_class_registry
        class_obj = json_class_registry.get(json_class, None)
        if class_obj is None:
            return error_response(message='{} is not defined'.format(json_class))
        return class_obj.context


# noinspection PyMethodMayBeStatic
@api.route('/context')
class Context(flask_restplus.Resource):

    def get(self):
        from sanskrit_ld.helpers.context_helper import context
        return context
