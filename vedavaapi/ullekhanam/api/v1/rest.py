# import json
# import os
from collections import OrderedDict

import flask_restplus
from flask import request
# from sanskrit_ld.helpers import db_helper
from sanskrit_ld.helpers.validation_helper import OrphanResourceError
# from sanskrit_ld.schema import JsonObject
# from sanskrit_ld.schema.users import Permission
from vedavaapi.common.api_common import jsonify_argument, error_response, get_user, check_argument_type
from werkzeug.datastructures import FileStorage

from . import api
from .. import get_colln
from ..helper import *

# GET: /resources; selector_doc, start, len, sort DONE
# POST: /resources; entity or resources_array, files DONE
# DELETE: /resources; resource_ids_array DONE
# GET: /resources/<id> DONE
# GET: /resources/<id>/specific_resources; filter_doc DONE
# DELETE: /resources/<id>/specific_resources; filter_doc DONE
# GET: /resources/<id>/annotations; filter_doc DONE
# DELETE: /resources/<id>/annotations; filter_doc, include_file_annos DONE
# GET: /resources/<id>/specific_annotations; specific_resource_filter, annotation_filter; dereference_sprs DONE
# DELETE: /resources/<id>/specific_annotations; specific_anns_filter_doc DONE
# GET: /resources/<id>/files; DONE
# POST: /resources/<id>/files; fd, file  # for update also DONE
# GET: /resources/<id>/files/<id> DONE
# DELETE: /resources/<id>/files/<id> DONE
# POST: /resources/<id>/files/<id> DONE
# POST: /resources/tree DONE


permission_manager = UllekhanamPermissionManager()


@api.route('/resources')
class Resources(flask_restplus.Resource):

    white_listed_classes = ('JsonObject', 'WrapperObject', 'FileAnnotation')

    get_parser = api.parser()
    get_parser.add_argument('selector_doc', location='args', type=str, required=True)
    get_parser.add_argument('fields', location='args', type=str)
    get_parser.add_argument('associated_resources', location='args', type=str)
    get_parser.add_argument('start', location='args', type=int, required=True)
    get_parser.add_argument('numbers', location='args', type=int, required=True)
    get_parser.add_argument('sort_doc', location='args', type=str)

    post_parser = api.parser()
    post_parser.add_argument('resource_json', location='form', type=str, required=True)
    post_parser.add_argument('files', type=FileStorage, location='files')
    post_parser.add_argument('files_purpose', type=str, location='form')

    delete_parser = api.parser()
    delete_parser.add_argument('resource_ids', location='form', type=str, required=True)

    @api.expect(get_parser, validate=True)
    def get(self):
        args = self.get_parser.parse_args()
        colln = get_colln()

        selector_doc = jsonify_argument(args['selector_doc'], key='selector_doc')
        check_argument_type(selector_doc, (dict,), key='selector_doc')

        fields = jsonify_argument(args['fields'], key='fields')
        check_argument_type(fields, (list,), key='fields', allow_none=True)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        sort_doc = jsonify_argument(args['sort_doc'], key='sort_doc')
        check_argument_type(sort_doc, (dict, list), key='sort_doc', allow_none=True)

        ops = OrderedDict()
        if sort_doc is not None:
            ops['sort'] = [sort_doc]
        ops['skip'] = [args['start']]
        ops['limit'] = [args['numbers']]

        try:
            resource_reprs = list(db_helper.read_and_do(colln, selector_doc, ops, fields=fields, return_generator=True))
        except (TypeError, ValueError):
            return error_response(message='arguments to operations seems invalid', code=400)
        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, resource_reprs, associated_resources_request_doc)
        return resource_reprs

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        resource_doc = jsonify_argument(args['resource_json'], key='resource_json')
        check_argument_type(resource_doc, (dict, list), key='resource_json')

        created_docs = []

        resource_docs = resource_doc if isinstance(resource_doc, list) else [resource_doc]

        '''
        TODO thought: can check integrity of all resources first,
        and then after ensuring all has integrity, we can proceed.
        instead of deleting some, and then halt at some
        '''

        for n, doc in enumerate(resource_docs):
            # noinspection PyBroadException
            try:
                resource = JsonObject.make_from_dict(doc)
                if resource.json_class in self.white_listed_classes:
                    raise TypeError('object type is not supported')
                handle_creation_details(colln, user, resource)
                resource.validate()
            except Exception as e:
                return error_response(
                    message='{} th JsonObject\'s schema is invalid'.format(n),
                    code=404, posted=created_docs, errorAt=n, error=str(e)
                )
            try:
                created_doc = db_helper.update(colln, resource, user, permission_manager=permission_manager)
                created_docs.append(created_doc)
            except OrphanResourceError:
                return error_response(message="cannot leave dependent one as an orphan", code=404)

        if isinstance(resource_doc, dict):
            resource_id = created_docs[0]['_id']
            files = request.files.getlist("files")
            purpose = args['files_purpose']
            for f in files:
                save_file(colln, user, resource_id, f, purpose)
        return created_docs

    @api.expect(delete_parser, validate=True)
    def delete(self):
        args = self.delete_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        resource_ids = jsonify_argument(args['resource_ids'])
        check_argument_type(resource_ids, (list,))

        ids_validity = False not in [isinstance(_id, str) for _id in resource_ids]
        if not ids_validity:
            return error_response(message='ids should be strings', code=404)

        delete_report = []

        for _id in resource_ids:
            deleted, deleted_res_ids = db_helper.delete(colln, _id, user, permission_manager=permission_manager)
            for deleted_res_id in deleted_res_ids:
                delete_resource_dir(deleted_res_id)
            delete_report.append({
                "deleted": deleted,
                "deleted_dependents_count": len(deleted_res_ids)
            })

        return delete_report


# noinspection PyMethodMayBeStatic
@api.route('/resources/<string:resource_id>')
class ResourceObject(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('associated_resources', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        resource = db_helper.read_by_id(colln, resource_id)
        if resource is None:
            return error_response(message="resource not found", code=404)

        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, [resource], associated_resources_request_doc)
        return resource


@api.route('/resources/<string:resource_id>/sections')
class SpecificResources(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)
    get_parser.add_argument('fields', location='args', type=str)
    get_parser.add_argument('associated_resources', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        fields = jsonify_argument(args['fields'], key='fields')
        check_argument_type(fields, (list,), key='fields', allow_none=True)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        specific_resources = list(db_helper.specific_resources(
            colln, resource_id, filter_doc=filter_doc, fields=fields, return_generator=True
        ))
        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, specific_resources, associated_resources_request_doc)
        return specific_resources

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        deleted_all, deleted_res_ids = db_helper.delete_specific_resources(
            colln, resource_id, user, filter_doc=filter_doc, permission_manager=permission_manager
        )
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/annotations')
class Annotations(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)
    get_parser.add_argument('fields', location='args', type=str)
    get_parser.add_argument('associated_resources', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        fields = jsonify_argument(args['fields'], key='fields')
        check_argument_type(fields, (list,), key='fields', allow_none=True)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        annotations = list(db_helper.annotations(
            colln, resource_id, filter_doc=filter_doc, fields=fields, return_generator=True
        ))
        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, annotations, associated_resources_request_doc)
        return annotations

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        deleted_all, deleted_res_ids = db_helper.delete_annotations(
            colln, resource_id, user, filter_doc=filter_doc, permission_manager=permission_manager
        )
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/files')
class Files(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)

    post_parser = api.parser()
    post_parser.add_argument('files', type=FileStorage, location='files', required=True)
    post_parser.add_argument('files_purpose', type=str, location='form')

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        file_annos = db_helper.files(colln, resource_id, filter_doc=filter_doc)
        for f in file_annos:
            f.pop('body', None)
        return file_annos

    @api.expect(post_parser, validate=True)
    def post(self, resource_id):
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        files = request.files.getlist("files")
        purpose = args['files_purpose']
        file_annos = []
        for f in files:
            anno = save_file(colln, user, resource_id, f, purpose).to_json_map()
            anno.pop('body', None)
            file_annos.append(anno)
        return file_annos


# noinspection PyMethodMayBeStatic
@api.route('/files/<string:file_id>')
class File(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('file', type=FileStorage, location='files')

    def get(self, file_id):
        colln = get_colln()
        file_anno_doc = db_helper.read_by_id(colln, file_id)
        if file_anno_doc is None:
            return error_response(message="file not found", code=404)

        file_anno = JsonObject.make_from_dict(file_anno_doc)
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
        # noinspection PyUnusedLocal
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)
        files = request.files.getlist("file")

        file_anno_doc = db_helper.read_by_id(colln, file_id)
        if file_anno_doc is None:
            return error_response(message="file not found", code=404)

        file_anno = JsonObject.make_from_dict(file_anno_doc)
        target_resource_id = file_anno.target
        target_resource = JsonObject.make_from_dict(db_helper.read_by_id(colln, target_resource_id))

        has_update_permission = permission_manager.has_persmission(user, Permission.UPDATE, obj=target_resource)

        if not has_update_permission:
            return error_response(message="user has no permission for this operation", code=403)
        for f in files:
            full_path = resource_file_path(target_resource_id, file_anno.body.path)
            os.remove(full_path)
            f.save(full_path)
            return {"success": True}

    def delete(self, file_id):
        colln = get_colln()
        user = get_user(required=True)

        try:
            delete_resource_file(colln, user, file_id)
        except PermissionError:
            return error_response(message="user has no permission for this operation", code=403)
        return {"success": True}


@api.route('/trees')
class Trees(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('trees', type=str, location='form', required=True)

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_user(required=True)

        trees = jsonify_argument(args['trees'], key='trees')
        check_argument_type(trees, (list,), key='trees')

        result_trees = []
        try:
            for i, tree in enumerate(trees):
                # noinspection PyTypeChecker
                result_tree = update_tree(colln, user, tree, 'tree{}'.format(i), None)
                result_trees.append(result_tree)
        except TreeCrawlError as e:
            print(e)
            return error_response(
                message="error in tree crawling",
                code=404,
                error_position=e.tree_position,
                succeded_trees=result_trees,
                error=str(e.error),
                node_json=e.node_json
            )
        return result_trees


@api.route('/trees/<root_node_id>')
class Tree(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('max_depth', location='args', type=int, default=1, required=True)
    get_parser.add_argument('section_filter', location='args', type=str)
    get_parser.add_argument('annotation_filter', location='args', type=str)
    get_parser.add_argument('section_fields', location='args', type=str)
    get_parser.add_argument('annotation_fields', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, root_node_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        max_depth = args['max_depth']
        specific_resource_filter = jsonify_argument(args['section_filter']) or {}
        annotation_filter = jsonify_argument(args['annotation_filter']) or {}

        specific_resource_fields = jsonify_argument(args['section_fields'])
        annotation_fields = jsonify_argument(args['annotation_fields'])

        root_node = db_helper.read_by_id(colln, root_node_id)
        tree = read_tree(
            colln, root_node, max_depth,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_fields=specific_resource_fields,
            annotation_fields=annotation_fields)
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
@api.route('/contexts')
class Contexts(flask_restplus.Resource):

    def get(self):
        from sanskrit_ld.schema import json_class_registry

        contexts = {}
        for k, v in json_class_registry.items():
            if not hasattr(v, 'context'):
                continue
            contexts[k] = v.context
        return contexts


# noinspection PyMethodMayBeStatic
@api.route('/contexts/<json_class>')
class Context(flask_restplus.Resource):

    def get(self, json_class):
        from sanskrit_ld.schema import json_class_registry
        class_obj = json_class_registry.get(json_class, None)
        if class_obj is None:
            return error_response(message='{} is not defined'.format(json_class))
        return class_obj.context
