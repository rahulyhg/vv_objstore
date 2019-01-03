import os
from collections import OrderedDict

import flask_restplus
from flask import request
from sanskrit_ld.helpers import db_helper
from sanskrit_ld.helpers.permissions_helper import PermissionResolver
from sanskrit_ld.schema import JsonObject
from sanskrit_ld.schema.base import ObjectPermissions
from vedavaapi.common.api_common import jsonify_argument, error_response, check_argument_type, get_current_user_id, \
    get_user, get_current_org
from werkzeug.datastructures import FileStorage

from . import api
from .. import get_colln, resource_file_path
from ...helpers.resources_helper import attach_associated_resources, read_tree, modified_projection
from ...helpers.resources_helper import save_file, delete_resource_file, delete_resource_dir
from ...helpers.resources_helper import create_or_update, get_resource, get_resource_json
from ...helpers.resources_helper import update_tree, TreeValidationError


# GET: /resources; selector_doc, start, len, sort DONE
# POST: /resources; entity or resources_array, files DONE
# DELETE: /resources; resource_ids_array DONE
# GET: /resources/<id> DONE
# GET: /resources/<id>/specific_resources; filter_doc DONE
# DELETE: /resources/<id>/specific_resources; filter_doc DONE
# GET: /resources/<id>/annotations; filter_doc DONE
# DELETE: /resources/<id>/annotations; filter_doc, include_file_annos DONE
# GET: /resources/<id>/files; DONE
# POST: /resources/<id>/files; fd, file  # for update also DONE
# GET: /files/<id> DONE
# DELETE: /files/<id> DONE
# POST: /files/<id> DONE
# POST: /resources/tree DONE


def get_current_user(required=True):
    current_org_name = get_current_org()
    current_user_id = get_current_user_id(required=required)
    if not required and not current_user_id:
        return None
    return get_user(current_org_name, _id=current_user_id)


@api.route('/resources')
class Resources(flask_restplus.Resource):

    white_listed_classes = ('JsonObject', 'WrapperObject', 'FileAnnotation')

    get_parser = api.parser()
    get_parser.add_argument('selector_doc', location='args', type=str, required=True)
    get_parser.add_argument('projection', location='args', type=str)
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

        projection = jsonify_argument(args['projection'], key='projection')
        check_argument_type(projection, (dict,), key='projection', allow_none=True)
        if projection is not None and 0 in projection.values() and 1 in projection.values():
            return error_response(message='invalid projection', code=400)

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
            resource_reprs = list(colln.find_and_do(
                selector_doc, ops,
                projection=projection, return_generator=True
            ))
        except (TypeError, ValueError):
            return error_response(message='arguments to operations seems invalid', code=400)
        except PermissionError:
            return error_response(message='user have no permission for this operation', code=403)

        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, resource_reprs, associated_resources_request_doc)
        return resource_reprs

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        current_user = get_current_user(required=True)

        resource_doc = jsonify_argument(args['resource_json'], key='resource_json')
        check_argument_type(resource_doc, (dict, list), key='resource_json')

        created_docs = []

        resource_docs = resource_doc if isinstance(resource_doc, list) else [resource_doc]

        for n, doc in enumerate(resource_docs):
            # noinspection PyBroadException
            try:
                resource = JsonObject.make_from_dict(doc)
                created_doc = create_or_update(colln, resource, current_user)
                created_docs.append(created_doc)
            except Exception as e:
                return error_response(message=str(e), code=403)

        if isinstance(resource_doc, dict):
            resource_id = created_docs[0]['_id']
            files = request.files.getlist("files")
            purpose = args['files_purpose']
            for f in files:
                save_file(colln, current_user, resource_id, f, purpose)
        return created_docs

    @api.expect(delete_parser, validate=True)
    def delete(self):
        args = self.delete_parser.parse_args()
        colln = get_colln()
        user = get_current_user(required=True)

        resource_ids = jsonify_argument(args['resource_ids'])
        check_argument_type(resource_ids, (list,))

        ids_validity = False not in [isinstance(_id, str) for _id in resource_ids]
        if not ids_validity:
            return error_response(message='ids should be strings', code=404)

        delete_report = []

        for _id in resource_ids:
            deleted, deleted_res_ids = db_helper.delete_tree(colln, _id, user)
            for deleted_res_id in deleted_res_ids:
                delete_resource_dir(deleted_res_id)
            delete_report.append({
                "deleted": deleted,
                "deleted_resources_count": len(deleted_res_ids)
            })

        return delete_report


# noinspection PyMethodMayBeStatic
@api.route('/resources/<string:resource_id>')
class ResourceObject(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('associated_resources', location='args', type=str)
    get_parser.add_argument('projection', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user = get_current_user(required=False)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        projection = jsonify_argument(args['projection'], 'projection')
        check_argument_type(projection, (dict,), key='projection', allow_none=True)
        if projection is not None and 0 in projection.values() and 1 in projection.values():
            return error_response(message='invalid projection', code=400)

        resource_permissions_projection = get_resource(
            colln, _id=resource_id, projection={"permissions": 1, "target": 1, "source": 1, "_id": 1})
        if resource_permissions_projection is None:
            return error_response(message="resource not found", code=404)

        if not PermissionResolver.resolve_permission(
                resource_permissions_projection, ObjectPermissions.READ, current_user, colln):
            return error_response(message='permission denied', code=403)

        resource = get_resource(colln, _id=resource_id, projection=projection)

        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, [projection], associated_resources_request_doc)
        return resource.to_json_map()


@api.route('/resources/<string:resource_id>/sections')
class SpecificResources(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('associated_resources', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        projection = jsonify_argument(args['projection'], key='projection')
        check_argument_type(projection, (list,), key='projection', allow_none=True)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        specific_resources = list(db_helper.specific_resources(
            colln, resource_id, filter_doc=filter_doc, projection=projection, return_generator=True
        ))
        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, specific_resources, associated_resources_request_doc)
        return specific_resources

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        user = get_current_user(required=True)

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        deleted_all, deleted_res_ids = db_helper.delete_specific_resources(
            colln, resource_id, user, filter_doc=filter_doc
        )
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/annotations')
class Annotations(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)
    get_parser.add_argument('projection', location='args', type=str)
    get_parser.add_argument('associated_resources', location='args', type=str)

    delete_parser = api.parser()
    delete_parser.add_argument('filter_doc', location='form', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        projection = jsonify_argument(args['projection'], key='projection')
        check_argument_type(projection, (list,), key='projection', allow_none=True)

        associated_resources_request_doc = jsonify_argument(args['associated_resources'], 'associated_resources')
        check_argument_type(associated_resources_request_doc, (dict,), key='associated_resources', allow_none=True)

        annotations = list(db_helper.annotations(
            colln, resource_id, filter_doc=filter_doc, projection=projection, return_generator=True
        ))
        if associated_resources_request_doc is not None:
            attach_associated_resources(colln, annotations, associated_resources_request_doc)
        return annotations

    @api.expect(delete_parser, validate=True)
    def delete(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        user = get_current_user(required=True)

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        deleted_all, deleted_res_ids = db_helper.delete_annotations(
            colln, resource_id, user, filter_doc=filter_doc
        )
        return {
            "deleted_all": deleted_all,
            "deleted_res_ids": deleted_res_ids
        }


@api.route('/resources/<string:resource_id>/files')
class Files(flask_restplus.Resource):

    get_parser = api.parser()
    get_parser.add_argument('filter_doc', location='args', type=str)
    get_parser.add_argument('projection', location='args', type=str)

    post_parser = api.parser()
    post_parser.add_argument('files', type=FileStorage, location='files', required=True)
    post_parser.add_argument('files_purpose', type=str, location='form')

    @api.expect(get_parser, validate=True)
    def get(self, resource_id):
        args = self.get_parser.parse_args()
        colln = get_colln()

        filter_doc = jsonify_argument(args['filter_doc'], key='filter_doc') or {}
        check_argument_type(filter_doc, (dict,), key='filter_doc')

        projection = jsonify_argument(args['projection'], key='projection')
        check_argument_type(projection, (list,), key='projection', allow_none=True)

        file_annos = db_helper.files(colln, resource_id, filter_doc=filter_doc, projection=projection)
        for f in file_annos:
            f.pop('body', None)
        return file_annos

    @api.expect(post_parser, validate=True)
    def post(self, resource_id):
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_current_user(required=True)

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
        current_user = get_current_user(required=False)
        file_anno = get_resource(colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

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
        current_user = get_current_user(required=True)
        files = request.files.getlist("file")

        file_anno = get_resource(colln, _id=file_id)
        if file_anno is None:
            return error_response(message="file not found", code=404)

        target_resource_id = file_anno.target

        has_update_permission = PermissionResolver.resolve_permission(
            file_anno, ObjectPermissions.UPDATE_CONTENT, current_user, colln)

        if not has_update_permission:
            return error_response(message="permission denied", code=403)
        for f in files:
            full_path = resource_file_path(target_resource_id, file_anno.body.path)
            os.remove(full_path)
            f.save(full_path)
            return {"success": True}

    def delete(self, file_id):
        colln = get_colln()
        user = get_current_user(required=True)

        try:
            delete_resource_file(colln, user, file_id)
        except Exception as e:
            return error_response(message=str(e), code=403)
        return {"success": True}


@api.route('/trees')
class Trees(flask_restplus.Resource):

    post_parser = api.parser()
    post_parser.add_argument('trees', type=str, location='form', required=True)
    post_parser.add_argument('root_node_projection', location='form', type=str)
    post_parser.add_argument('section_projection', location='form', type=str)
    post_parser.add_argument('annotation_projection', location='form', type=str)

    @api.expect(post_parser, validate=True)
    def post(self):
        args = self.post_parser.parse_args()
        colln = get_colln()
        user = get_current_user(required=True)

        root_node_projection = modified_projection(
            jsonify_argument(args['root_node_projection']), mandatory_attrs=['_id'])
        specific_resource_projection = modified_projection(
            jsonify_argument(args['section_projection']), mandatory_attrs=['_id'])
        annotation_projection = modified_projection(
            jsonify_argument(args['annotation_projection']), mandatory_attrs=['_id'])

        trees = jsonify_argument(args['trees'], key='trees')
        check_argument_type(trees, (list,), key='trees')

        result_trees = []
        try:
            for i, tree in enumerate(trees):
                result_tree = update_tree(
                    colln, user, tree, 'tree{}'.format(i), None,
                    root_node_projection=root_node_projection,
                    specific_resource_projection=specific_resource_projection,
                    annotation_projection=annotation_projection)
                result_trees.append(result_tree)

        except PermissionError:
            return error_response(message='user has no permission for this operation', code=401)

        except TreeValidationError as e:
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
    get_parser.add_argument('section_filter', location='args', type=str)
    get_parser.add_argument('annotation_filter', location='args', type=str)
    get_parser.add_argument('root_node_projection', location='args', type=str)
    get_parser.add_argument('section_projection', location='args', type=str)
    get_parser.add_argument('annotation_projection', location='args', type=str)

    @api.expect(get_parser, validate=True)
    def get(self, root_node_id):
        args = self.get_parser.parse_args()
        colln = get_colln()
        current_user = get_current_user(required=False)

        max_depth = args['max_depth']
        specific_resource_filter = jsonify_argument(args['section_filter']) or {}
        annotation_filter = jsonify_argument(args['annotation_filter']) or {}

        root_node_projection = modified_projection(
            jsonify_argument(args['root_node_projection']), mandatory_attrs=['_id'])
        specific_resource_projection = modified_projection(
            jsonify_argument(args['section_projection']), mandatory_attrs=['_id'])
        annotation_projection = modified_projection(
            jsonify_argument(args['annotation_projection']), mandatory_attrs=['_id'])

        root_node = get_resource_json(colln, root_node_id, projection=root_node_projection)
        if root_node is None:
            message = "resource with _id '{}' not found in this repo".format(root_node_id)
            return error_response(message=message, code=404)

        tree = read_tree(
            colln, root_node, max_depth,
            specific_resource_filter=specific_resource_filter,
            annotation_filter=annotation_filter,
            specific_resource_projection=specific_resource_projection,
            annotation_projection=annotation_projection)
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
