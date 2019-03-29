import json
import os
import sys
from collections import OrderedDict

import flask_restplus
from flask import request, g
from jsonschema import ValidationError

from sanskrit_ld.helpers.permissions_helper import PermissionResolver
from sanskrit_ld.schema.base import ObjectPermissions, Permission

from vedavaapi.common.api_common import jsonify_argument, error_response, check_argument_type, \
    abort_with_error_response, get_current_org, get_user, get_group

from vedavaapi.common import custom_args_parser
from vedavaapi.common.custom_args_parser import parse_json_args

from vedavaapi.common.token_helper import require_oauth, current_token
from vedavaapi.objectdb.helpers import objstore_helper, objstore_graph_helper, projection_helper, ObjModelException
from werkzeug.datastructures import FileStorage

from . import api
from .. import resource_file_path
from ..files_helper import save_file, delete_resource_file, delete_resource_dir


def _validate_projection(projection):
    try:
        projection_helper.validate_projection(projection)
    except ObjModelException as e:
        error = error_response(message=e.message, code=e.http_response_code)
        abort_with_error_response(error)


def get_requested_resource_jsons(args):

    json_parse_directives = {
        "selector_doc": {
            "allowed_types": (dict, ), "default": {}
        },
        "projection": {
            "allowed_types": (dict, ), "allow_none": True, "custom_validator": _validate_projection
        },
        "linked_resources": {
            "allowed_types": (dict, ), 'allow_none': True
        },
        "sort_doc": {
            "allowed_types": (dict, list), "allow_none": True
        }
    }

    args = parse_json_args(args, json_parse_directives)

    selector_doc = args['selector_doc']
    projection = args['projection']
    lrs_request_doc = args['linked_resources']
    sort_doc = args['sort_doc']

    ops = OrderedDict()
    if sort_doc is not None:
        ops['sort'] = [sort_doc]
    if args.get('start', None) is not None and args.get('count', 100) is not None:
        ops['skip'] = [args['start']]
        ops['limit'] = [args['count']]

    try:
        resource_repr_jsons = objstore_helper.get_read_permitted_resource_jsons(
            g.objstore_colln, current_token.user_id,
            current_token.group_ids, selector_doc, projection=projection, ops=ops
        )
    except (TypeError, ValueError):
        error = error_response(message='arguments to operations seems invalid', code=400)
        abort_with_error_response(error)
    except Exception as e:
        error = error_response(message='invalid arguments', code=400)
        abort_with_error_response(error)

    if lrs_request_doc is not None:
        # noinspection PyUnboundLocalVariable
        for rj in resource_repr_jsons:
            linked_resources = objstore_helper.get_linked_resource_ids(g.objstore_colln, rj['_id'], lrs_request_doc)
            rj['linked_resources'] = linked_resources
    return resource_repr_jsons


@api.route('/resources')
class Resources(flask_restplus.Resource):

    white_listed_classes = ('JsonObject', 'WrapperObject', 'FileAnnotation', 'User', 'UsersGroup')

    get_parser = api.parser()
    get_parser.add_argument(
        'selector_doc', location='args', type=str, default='{}',
        help='syntax is same as mongo query_doc. https://docs.mongodb.com/manual/tutorial/query-documents/'
    )
    get_parser.add_argument('projection', location='args', type=str, help='ex: {"permissions": 0}')
    get_parser.add_argument('linked_resources', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str, help='ex: [["created": 1], ["title.chars": -1]]')
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    # post payload parser
    post_parser = api.parser()
    post_parser.add_argument('resources_list', location='form', type=str, required=True)
    post_parser.add_argument('attachments', type=FileStorage, location='files')
    post_parser.add_argument('attachments_infos', type=str, location='form')
    post_parser.add_argument('return_projection', location='form', type=str)
    post_parser.add_argument('return_created_linked_resources', location='form', type=bool, default=True)
    post_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    post_json_parse_directives = {
        "resources_list": {"allowed_types": (list, )},
        "attachments_infos": {"allowed_infos": (list, ), "allow_none": True},
        "return_projection": {
            "allowed_types": (dict, ), "allow_none": True, "custom_validator": _validate_projection
        }
    }

    # delete payload parser
    delete_parser = api.parser()
    delete_parser.add_argument('resource_ids', location='form', type=str, required=True)
    delete_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    delete_json_parse_directives = {
        "resource_ids": {"allowed_types": (list, )}
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self):
        args = self.get_parser.parse_args()
        return get_requested_resource_jsons(args)

    @api.expect(post_parser, validate=True)
    @require_oauth()
    def post(self):
        args = self.post_parser.parse_args()
        args = parse_json_args(args, self.post_json_parse_directives)

        resource_jsons = args['resource_jsons']
        return_projection = args['return_projection']

        attachments_infos = args['attachments_infos']
        if attachments_infos is not None and len(attachments_infos) != len(resource_jsons):
            return error_response(
                message='attachments_infos should have one-to-one correspondence with resources', code=403
            )

        files = request.files.getlist("attachments")
        files_index = dict((f.filename, f) for f in files)

        return_created_lrs = args.get('return_created_linked_resources', True)

        created_resource_jsons = []
        for n, rj in enumerate(resource_jsons):
            try:
                if 'jsonClass' not in rj:
                    raise ObjModelException('jsonClass attribute should exist for update/creation', 403)

                created_resource_id = objstore_helper.create_or_update(
                    g.objstore_colln, rj,
                    current_token.user_id, current_token.group_ids, initial_agents=g.initial_agents)

                if created_resource_id is None:
                    created_resource_jsons.append(None)
                    continue
                created_resource_json = g.objstore_colln.get(
                    created_resource_id,
                    projection=projection_helper.modified_projection(return_projection, ["_id", "jsonClass"]))
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
                        g.objstore_colln, current_token.user_id, current_token.group_ids, created_resource_id,
                        files_index[attachment_file_name], attachment_purpose, initial_agents=g.initial_agents
                    )
                    # noinspection PyProtectedMember
                    created_linked_resource_ids['files'].append(file_anno._id)

                if return_created_lrs:
                    created_resource_json['created_linked_resources'] = created_linked_resource_ids

            except ObjModelException as e:
                return error_response(
                    message='action not allowed at resource {}'.format(n),
                    code=e.http_response_code, details={"error": e.message})
            except (ValidationError, TypeError) as e:
                return error_response(
                    message='schema validation error at resource {}'.format(n),
                    code=400, details={"error": str(e)})

        return created_resource_jsons

    @api.expect(delete_parser, validate=True)
    @require_oauth()
    def delete(self):
        args = self.delete_parser.parse_args()
        args = parse_json_args(args, self.delete_json_parse_directives)

        resource_ids = args['resource_ids']

        ids_validity = False not in [isinstance(_id, str) for _id in resource_ids]
        if not ids_validity:
            return error_response(message='ids should be strings', code=404)

        delete_report = []

        for resource_id in resource_ids:
            deleted, deleted_res_ids = objstore_helper.delete_tree(
                g.objstore_colln, resource_id, current_token.user_id, current_token.group_ids)
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
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    get_payload_json_parse_directives = {
        "linked_resources": {
            "allowed_types": (dict, ), "allow_none": True
        },
        "projection": {
            "allowed_types": (dict, ), "allow_none": True, "custom_validator": _validate_projection
        }
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        args = parse_json_args(args, self.get_payload_json_parse_directives)

        lrs_request_doc = args['linked_resources']
        projection = args['projection']

        resource_json = g.objstore_colln.find_one(
            objstore_helper.resource_selector_doc(resource_id), projection=None
        )
        if not resource_json:
            return error_response(message='resource not found', code=404)
        if not PermissionResolver.resolve_permission(
                resource_json, ObjectPermissions.READ,
                current_token.user_id, current_token.group_ids, g.objstore_colln):
            return error_response(message='permission denied', code=403)

        projection_helper.project_doc(resource_json, projection, in_place=True)

        if lrs_request_doc is not None:
            resource_json['linked_resources'] = objstore_helper.get_linked_resource_ids(
                g.objstore_colln, resource_id, lrs_request_doc)
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
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)
    delete_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    delete_payload_json_parse_directives = {
        "filter_doc": {
            "allowed_types": (dict,), "default": {}
        }
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.specific_resources_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resource_jsons(args)

    @api.expect(delete_parser, validate=True)
    @require_oauth()
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        args = parse_json_args(args, self.delete_payload_json_parse_directives)

        filter_doc = args['filter_doc']
        selector_doc = objstore_helper.specific_resources_selector_doc(resource_id, custom_filter_doc=filter_doc)

        deleted_all, deleted_res_ids = objstore_helper.delete_selection(
            g.objstore_colln, selector_doc, current_token.user_id, current_token.group_ids)
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
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)
    delete_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    delete_payload_json_parse_directives = {
        "filter_doc": {
            "allowed_types": (dict,), "default": {}
        }
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.annotations_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resource_jsons(args)

    @api.expect(delete_parser, validate=True)
    @require_oauth()
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        args = parse_json_args(args, self.delete_payload_json_parse_directives)

        filter_doc = args['filter_doc']
        selector_doc = objstore_helper.annotations_selector_doc(resource_id, custom_filter_doc=filter_doc)

        deleted_all, deleted_res_ids = objstore_helper.delete_selection(
            g.objstore_colln, selector_doc, current_token.user_id, current_token.group_ids)
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/agents')
class Agents(flask_restplus.Resource):

    post_delete_parser = api.parser()
    post_delete_parser.add_argument(
        'actions', location='form', type=str, required=True,
        help='any combination among {}'.format(str(ObjectPermissions.ACTIONS))
    )
    post_delete_parser.add_argument(
        'agents_set_name', location='form', type=str, required=True,
        choices=[Permission.GRANTED, Permission.WITHDRAWN, Permission.BLOCKED]
    )
    post_delete_parser.add_argument('user_ids', location='form', type=str, default='[]')
    post_delete_parser.add_argument('group_ids', location='form', type=str, default='[]')
    post_delete_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    post_delete_payload_json_parse_directives = {
        "actions": {
            "allowed_types": (list, )
        },
        "user_ids": {
            "allowed_types": (list, ), "default": []
        },
        "group_ids": {
            "allowed_types": (list,), "default": []
        }
    }

    @api.expect(post_delete_parser, validate=True)
    @require_oauth()
    def post(self, resource_id):
        current_org_name = get_current_org()
        args = parse_json_args(self.post_delete_parser.parse_args(), self.post_delete_payload_json_parse_directives)

        actions = args['actions']
        user_ids = args['user_ids']
        group_ids = args['group_ids']

        def get_user_fn(user_id, projection=None):
            return get_user(current_org_name, user_id, projection=projection)  # TODO!

        def get_group_fn(group_id, projection=None):
            return get_group(current_org_name, group_id, projection=projection)

        try:
            objstore_helper.add_to_permissions_agent_set(
                g.objstore_colln, resource_id, current_token.user_id, current_token.group_ids,
                actions, args['agents_set_name'], get_user_fn, get_group_fn,
                user_ids=user_ids, group_ids=group_ids)
        except ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        resource_json = g.objstore_colln.find_one(
            objstore_helper.resource_selector_doc(resource_id), projection={"permissions": 1})
        resource_permissions = resource_json['permissions']
        return resource_permissions

    @api.expect(post_delete_parser, validate=True)
    @require_oauth()
    def delete(self, resource_id):
        args = parse_json_args(self.post_delete_parser.parse_args(), self.post_delete_payload_json_parse_directives)

        actions = args['actions']
        user_ids = args['user_ids']
        group_ids = args['group_ids']

        try:
            objstore_helper.remove_from_permissions_agent_set(
                g.objstore_colln, resource_id, current_token.user_id, current_token.group_ids,
                actions, args['agents_set_name'],
                user_ids=user_ids, group_ids=group_ids)
        except ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        resource_json = g.objstore_colln.find_one(
            objstore_helper.resource_selector_doc(resource_id), projection={"permissions": 1})
        resource_permissions = resource_json['permissions']
        return resource_permissions


@api.route('/resources/<string:resource_id>/resolved_permissions')
class ResolvedPermissions(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('actions', location='args', type=str, default=None)
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    get_payload_json_parse_directives = {
        "actions": {
            "allowed_types": (list,)
        }
    }

    @api.expect(get_parser, validate=True)
    @require_oauth()
    def get(self, resource_id):
        if not current_token.user_id:
            return error_response(message='request should be on behalf of a user', code=400)
        args = parse_json_args(self.get_parser.parse_args(), self.get_payload_json_parse_directives)

        actions = args['actions']

        resource_json = g.objstore_colln.find_one(
            objstore_helper.resource_selector_doc(resource_id), projection=None
        )
        if not resource_json:
            return error_response(message='resource not found', code=404)

        referred_objects_graph = PermissionResolver.get_referred_objects_graph(
            g.objstore_colln, resource_json, {resource_json['_id']: resource_json})

        resolved_permissions = dict(
            (
                action,
                PermissionResolver.resolve_permission_on_obj_with_referred_graph(
                    resource_json, referred_objects_graph, action, current_token.user_id, current_token.group_ids)
             )
            for action in actions
        )
        return resolved_permissions


@api.route('/resources/<string:resource_id>/files')
class Files(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str, default='{}')
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int)
    get_parser.add_argument('count', location='args', type=int)
    get_parser.add_argument('sort_doc', location='args', type=str)
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    post_parser = api.parser()
    post_parser.add_argument('files', type=FileStorage, location='files', required=True)
    post_parser.add_argument('files_purpose', type=str, location='form')
    post_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self, resource_id):
        args = self.get_parser.parse_args()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')
        selector_doc = objstore_helper.files_selector_doc(resource_id, custom_filter_doc=filter_doc)
        args['selector_doc'] = json.dumps(selector_doc)

        return get_requested_resource_jsons(args)

    @api.expect(post_parser, validate=True)
    @require_oauth()
    def post(self, resource_id):
        args = self.post_parser.parse_args()

        files = request.files.getlist("files")
        purpose = args['files_purpose']
        file_annotation_jsons = []
        for f in files:
            file_annotation_json = save_file(
                g.objstore_colln, current_token.user_id, current_token.group_ids,
                resource_id, f, purpose, initial_agents=g.initial_agents).to_json_map()
            file_annotation_json.pop('body', None)
            file_annotation_jsons.append(file_annotation_json)
        return file_annotation_jsons


# noinspection PyMethodMayBeStatic
@api.route('/files/<string:file_id>')
class File(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('file', type=FileStorage, location='files')
    post_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    @require_oauth(token_required=False)
    def get(self, file_id):
        file_anno = objstore_helper.get_resource(g.objstore_colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

        if not PermissionResolver.resolve_permission(
                file_anno, ObjectPermissions.READ, current_token.user_id, current_token.group_ids, g.objstore_colln):
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
    @require_oauth()
    def post(self, file_id):
        files = request.files.getlist("file")

        file_anno = objstore_helper.get_resource(g.objstore_colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

        target_resource_id = file_anno.target

        if not PermissionResolver.resolve_permission(
                file_anno, ObjectPermissions.UPDATE_CONTENT,
                current_token.user_id, current_token.group_ids, g.objstore_colln):
            return error_response(message='permission denied', code=403)

        for f in files:
            full_path = resource_file_path(target_resource_id, file_anno.body.path)
            os.remove(full_path)
            f.save(full_path)
            return {"success": True}

    @require_oauth()
    def delete(self, file_id):
        try:
            delete_resource_file(g.objstore_colln, current_token.user_id, current_token.group_ids, file_id)
        except Exception as e:
            return error_response(message=str(e), code=403)
        return {"success": True}


#  deprecated
@api.route('/trees')
class Trees(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('trees', type=str, location='form', required=True)
    post_parser.add_argument('root_node_return_projection', location='form', type=str)
    post_parser.add_argument('sections_return_projection', location='form', type=str)
    post_parser.add_argument('annotations_return_projection', location='form', type=str)
    post_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    @api.expect(post_parser, validate=True)
    @require_oauth()
    def post(self):
        args = self.post_parser.parse_args()

        root_node_return_projection = projection_helper.modified_projection(
            jsonify_argument(args['root_node_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(root_node_return_projection)
        specific_resources_return_projection = projection_helper.modified_projection(
            jsonify_argument(args['sections_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(specific_resources_return_projection)
        annotations_return_projection = projection_helper.modified_projection(
            jsonify_argument(args['annotations_return_projection']), mandatory_attrs=['_id'])
        _validate_projection(annotations_return_projection)

        trees = jsonify_argument(args['trees'], key='trees')
        check_argument_type(trees, (list,), key='trees')

        result_trees = []
        try:
            for i, tree in enumerate(trees):
                result_tree = objstore_helper.update_tree(
                    g.objstore_colln, current_token.user_id, current_token.group_ids, tree, 'tree{}'.format(i), None,
                    root_node_return_projection=root_node_return_projection,
                    specific_resources_return_projection=specific_resources_return_projection,
                    annotations_return_projection=annotations_return_projection,
                    initial_agents=g.initial_agents)
                result_trees.append(result_tree)
        except objstore_helper.TreeValidationError as e:
            return error_response(
                message="error in posting tree",
                code=e.http_status_code,
                invalid_node_path=e.invalid_node_path,
                invalid_node_json=e.invalid_node_json,
                error=str(e.error),
                succeded_trees=result_trees
            )
        except (ValidationError, TypeError) as e:
            return error_response(message='schema validation error', error=str(e), code=400)

        return result_trees


#  deprecated
@api.route('/trees/<root_node_id>')
class Tree(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('max_depth', location='args', type=int, default=1, required=True)
    get_parser.add_argument('sections_filter', location='args', type=str)
    get_parser.add_argument('annotations_filter', location='args', type=str)
    get_parser.add_argument('root_node_projection', location='args', type=str)
    get_parser.add_argument('sections_projection', location='args', type=str)
    get_parser.add_argument('annotations_projection', location='args', type=str)
    get_parser.add_argument(
        'Authorization', location='headers', type=str, required=False,
        help='should be in form of "Bearer <access_token>"'
    )

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self, root_node_id):
        args = self.get_parser.parse_args()

        max_depth = args['max_depth']
        specific_resources_filter = jsonify_argument(args['sections_filter']) or {}
        annotations_filter = jsonify_argument(args['annotations_filter']) or {}

        root_node_projection = projection_helper.modified_projection(
            jsonify_argument(args['root_node_projection']), mandatory_attrs=['_id'])
        _validate_projection(root_node_projection)
        specific_resources_projection = projection_helper.modified_projection(
            jsonify_argument(args['sections_projection']), mandatory_attrs=['_id'])
        _validate_projection(specific_resources_projection)
        annotations_projection = projection_helper.modified_projection(
            jsonify_argument(args['annotations_projection']), mandatory_attrs=['_id'])
        _validate_projection(annotations_projection)

        try:
            tree = objstore_helper.read_tree(
                g.objstore_colln, root_node_id, max_depth, current_token.user_id, current_token.group_ids,
                specific_resources_filter=specific_resources_filter,
                annotations_filter=annotations_filter,
                root_node_projection=root_node_projection,
                specific_resources_projection=specific_resources_projection,
                annotations_projection=annotations_projection
            )
        except ObjModelException as e:
            return error_response(message=e.message, code=e.http_response_code)

        return tree


# noinspection PyMethodMayBeStatic
@api.route('/graph')
class Graph(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument(
        'start_nodes_selector', type=str, location='args', required=True
    )
    get_parser.add_argument(
        'traverse_key_filter_maps_list', type=str, location='args', default='[{"source": {}, "target": {}}]'
    )
    get_parser.add_argument(
        'direction', type=str, location='args', choices=['referred', 'referrer'], required=True
    )
    get_parser.add_argument(
        'max_hops', type=int, location='args', default=0
    )
    get_parser.add_argument(
        'json_class_projection_map', type=str, location='args', default=None
    )

    get_payload_json_parse_directives = {
        "start_nodes_selector": {"allowed_types": (dict, )},
        "traverse_key_filter_maps_list": {"allowed_types": (list, )},
        "json_class_projection_map": {"allowed_types": (dict, )}
    }

    post_parser = api.parser()
    post_parser.add_argument(
        'graph', type=str, location='form', required=True
    )
    post_parser.add_argument(
        'ool_data_graph', type=str, location='form', required=False
    )
    post_parser.add_argument(
        'files', type=FileStorage, location='files'
    )
    post_parser.add_argument(
        'should_return_resources', type=str, location='form', choices=['true', 'false'], default='false'
    )
    post_parser.add_argument(
        'should_return_oold_resources', type=str, location='form', choices=['true', 'false'], default='false'
    )
    post_parser.add_argument(
        'response_projection_map', type=str, location='form'
    )
    post_parser.add_argument(
        'upsert_if_primary_keys_matched', type=str, location='form', choices=['true', 'false'], default='false'
    )
    post_parser.add_argument(
        'Authorization', location='headers', type=str, required=True,
        help='should be in form of "Bearer <access_token>"'
    )

    post_payload_json_parse_directives = {
        "graph": {"allowed_types": (dict, )},
        "ool_data_graph": {"allowed_types": (dict, ), "default": {}},
        "should_return_resources": {"allowed_types": (bool, ), "default": False},
        "should_return_oold_resources": {"allowed_types": (bool, ), "default": False},
        "response_projection_map": {"allowed_types": (dict, ), "default": {}},
        "upsert_if_primary_keys_matched": {"allowed_types": (bool, ), "default": False}
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self):
        args = parse_json_args(
            self.get_parser.parse_args(), self.get_payload_json_parse_directives)

        start_nodes_selector = args['start_nodes_selector']

        traverse_key_filter_maps_list = args['traverse_key_filter_maps_list']

        for kf_map in traverse_key_filter_maps_list:
            if not isinstance(kf_map, dict):
                return error_response(message='invalid traverse_key_filter_maps_list', code=400)

        json_class_projection_map = args['json_class_projection_map']

        direction = args.get('direction')
        max_hops = args.get('max_hops', 0)

        graph, start_nodes_ids = objstore_graph_helper.get_graph(
            g.objstore_colln, start_nodes_selector, {}, traverse_key_filter_maps_list, direction, max_hops,
            current_token.user_id, current_token.group_ids)
        objstore_graph_helper.project_graph_nodes(graph, json_class_projection_map, in_place=True)

        return {"graph": graph, "start_nodes_ids": start_nodes_ids}, 200

    @api.expect(post_parser, validate=True)
    @require_oauth()
    def post(self):
        args = parse_json_args(
            self.post_parser.parse_args(), self.post_payload_json_parse_directives)

        graph = args['graph']
        ool_data_graph = args['ool_data_graph']

        should_return_resources = args['should_return_resources']
        should_return_oold_resources = args['should_return_oold_resources']

        upsert_if_primary_keys_matched = args['upsert_if_primary_keys_matched']
        response_projection_map = args['response_projection_map']

        for json_class in response_projection_map.keys():
            _validate_projection(response_projection_map[json_class])

        files = request.files.getlist("files")
        files_map = dict((f.filename, f) for f in files)

        try:
            graph_ids_to_uids_map, ool_data_graph_ids_to_uids_map = objstore_graph_helper.post_graph_with_ool_data(
                g.objstore_colln, g.data_dir_path,
                current_token.user_id, current_token.group_ids,
                graph, ool_data_graph, files_map,
                initial_agents=g.initial_agents, upsert_if_primary_keys_matched=upsert_if_primary_keys_matched
            )
        except objstore_graph_helper.GraphValidationError as e:
            return error_response(
                message=str(e),
                code=e.http_status_code,
                error=str(e.error)
            )

        response = {}
        if should_return_resources:
            response['graph'] = objstore_graph_helper.get_projected_graph_from_ids_map(
                g.objstore_colln, graph_ids_to_uids_map, response_projection_map
            )
        else:
            response['graph'] = graph_ids_to_uids_map

        if should_return_oold_resources:
            response['ool_data_graph'] = objstore_graph_helper.get_projected_graph_from_ids_map(
                g.objstore_colln, ool_data_graph_ids_to_uids_map, response_projection_map
            )
        else:
            response['ool_data_graph'] = ool_data_graph_ids_to_uids_map

        return response, 200


@api.route('/network')
class Network(flask_restplus.Resource):

    get_parser =api.parser()
    get_parser.add_argument(
        'start_nodes_selector', type=str, location='args', required=True
    )
    get_parser.add_argument(
        'edge_filters_list', type==str, location='args', required=True
    )
    get_parser.add_argument(
        'from_link_field', type=str, location='args', required=True
    )
    get_parser.add_argument(
        'to_link_field', type=str, location='args', required=True
    )
    get_parser.add_argument(
        'max_hops', type=int, location='args', default=0
    )
    get_parser.add_argument(
        'json_class_projection_map', type=str, location='args', default=None
    )

    get_payload_json_parse_directives = {
        "start_nodes_selector": {"allowed_types": (dict, )},
        "edge_filters_list": {"allowed_types": (list, )},
        "json_class_projection_map": {"allowed_types": (dict, ), "default": {}}
    }

    @api.expect(get_parser, validate=True)
    @require_oauth(token_required=False)
    def get(self):
        args = parse_json_args(
            self.get_parser.parse_args(), self.get_payload_json_parse_directives)

        start_nodes_selector = args['start_nodes_selector']
        edge_filters_list = args['edge_filters_list']

        for ef in edge_filters_list:
            if not isinstance(ef, dict):
                return error_response(message='invalid edge_filters_list', code=400)

        json_class_projection_map = args['json_class_projection_map']

        from_link_field = args.get('from_link_field')
        to_link_field = args.get('to_link_field')
        max_hops = args.get('max_hops', 0)

        network, start_nodes_ids = objstore_graph_helper.get_network(
            g.objstore_colln, start_nodes_selector, {"nodes": {}, "edges": {}}, edge_filters_list,
            from_link_field, to_link_field, max_hops, current_token.user_id, current_token.group_ids)
        objstore_graph_helper.project_graph_nodes(network['nodes'], json_class_projection_map, in_place=True)
        objstore_graph_helper.project_graph_nodes(network['edges'], json_class_projection_map, in_place=True)

        return {
            "network": network,
            "start_nodes_ids": start_nodes_ids
        }, 200

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
@api.route('/presentation_schemas/<json_class>')
class PresentationSchema(flask_restplus.Resource):

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
