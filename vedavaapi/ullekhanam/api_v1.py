"""
A general API to access and annotate a text corpus.

API docs `here`_

.. _here: http://api.vedavaapi.org/py/ullekhanam/docs
"""

import os
import sys
import traceback
import logging
import cv2
from os.path import join

from PIL import Image
from docimage import DocImage
import flask_restplus
from werkzeug.datastructures import FileStorage
import sanskrit_data.schema.common as common_data_containers
from flask import Blueprint, request
from sanskrit_data.schema.common import JsonObject

from vedavaapi.common import *
from sanskrit_data.schema import common, books, ullekhanam
from vedavaapi.ullekhanam.backend import get_db

logging.basicConfig(
  level=logging.INFO,
  format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)

URL_PREFIX = '/v1'
api_blueprint = Blueprint(name='ullekhanam_api', import_name=__name__)
api = flask_restplus.Api(app=api_blueprint, version='1.0', title='vedavaapi py ullekhanam API',
                         description='For detailed intro and to report issues: see <a href="https://github.com/vedavaapi/vedavaapi_py_api">here</a>. '
                                     'For using some API, you need to log in using <a href="../auth/v1/oauth_login/google">google</a>.'
                         # We are not linking to  <a href="v1/schemas"> below since it results in an error on Chrome. See https://github.com/vedavaapi/vedavaapi_py_api/issues/3 
                                     'For a list of JSON schema-s this API uses (referred to by name in docs) see the schemas API below.</a>. '
                                     'Please also see videos <a href="https://www.youtube.com/playlist?list=PL63uIhJxWbghuZDlqwRLpPoPPFDNQppR6">here</a>, <a href="https://docs.google.com/presentation/d/1Wx1rxf5W5VpvSS4oGkGpp28WPPM57CUx41dGHC4ed80/edit">slides</a>,  <a href="http://sanskrit-data.readthedocs.io/en/latest/sanskrit_data_schema.html#class-diagram" > class diagram </a> as well as the sources ( <a href="http://sanskrit-data.readthedocs.io/en/latest/_modules/sanskrit_data/schema/books.html#BookPortion">example</a> ) - It might help you understand the schema more easily.<BR>'
                                     'A list of REST and non-REST API routes avalilable on this server: <a href="../sitemap">sitemap</a>. ',
                         default_label=api_blueprint.name,
                         prefix=URL_PREFIX, doc='/docs')

def is_extension_allowed(filename, allowed_extensions_with_dot):
  [fname, ext] = os.path.splitext(filename)
  return ext in allowed_extensions_with_dot

json_node_model = api.model('JsonObjectNode', common_data_containers.JsonObjectNode.schema)

@api.route('/dbs/<string:db_id>/books')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
class BookList(flask_restplus.Resource):
  get_parser = api.parser()
  get_parser.add_argument('pattern', location='args', type='string', default=None)

  @api.expect(get_parser, validate=True)
  # Marshalling as below does not work.
  # @api.marshal_list_with(json_node_model)
  def get(self, db_id):
    """ Get booklist.
    
    :return: a list of JsonObjectNode json-s.
    """
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    booklist = [book.to_json_map() for book in db.list_books()]
    # logging.debug(booklist)
    return booklist, 200

  post_parser = api.parser()
  # The below only results in the ability to upload a single file from the SwaggerUI. TODO: Surpass this limitation.
  post_parser.add_argument('in_files', type=FileStorage, location='files')
  # post_parser.add_argument('jsonStr', location='json') would lead to an error - "flask_restplus.errors.SpecsError: Can't use formData and body at the same time"
  post_parser.add_argument('book_json', location='form', type='string')

  @api.expect(post_parser, validate=True)
  @api.doc(responses={
    200: 'Update success.',
    401: 'Unauthorized. Use <a href="../auth/v1/oauth_login/google">google</a> to login and request access at https://github.com/vedavaapi/vedavaapi_py_api .',
    405: "book with same ID already exists.",
    417: 'JSON schema validation error.',
    418: 'Illegal file extension.',
    419: 'Error saving page files.',
  })
  def post(self, db_id):
    """Handle uploading files.
    
    :return: Book details in a json tree like:
      {"content": BookPortionObj, "children": [JsonObjectNode with BookPortion_Pg1, JsonObjectNode with BookPortion_Pg2]}    
    """
    from vedavaapi.common import check_permission
    if not check_permission(db_name=db_id):
      return "", 401

    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404

    book_json = request.form.get("book_json")
    logging.info(book_json)

    # To avoid having to do rollbacks, we try to prevalidate the data to the maximum extant possible.
    book = common_data_containers.JsonObject.make_from_pickledstring(book_json)
    if book.base_data != "image" or not isinstance(book, books.BookPortion) :
      message = {
        "message": "Only image books can be uploaded with this API."
      }
      return message, 417

    if hasattr(book, "_id"):
      message = {
        "message": "overwriting " + book._id + " is not allowed."
      }
      logging.warning(str(message))
      return message, 405

    # Check the files
    for uploaded_file in request.files.getlist("in_files"):
      input_filename = os.path.basename(uploaded_file.filename)
      allowed_extensions = {".jpg", ".png", ".gif"}
      if not is_extension_allowed(input_filename, allowed_extensions):
        message = {
          "message": "Only these extensions are allowed: %(exts)s, but filename is %(input_filename)s" % dict(exts=str(allowed_extensions), input_filename=input_filename) ,
        }
        logging.error(message)
        return message, 418

    # Book is validated here.
    book = book.update_collection(db_interface=db, user=get_user())

    try:
      page_index = -1
      for uploaded_file in request.files.getlist("in_files"):
        page_index = page_index + 1
        # TODO: Add image update subroutine and call that.
        page = books.BookPortion.from_details(
            title="pg_%000d" % page_index, base_data="image", portion_class="page",
            targets=[books.BookPositionTarget.from_details(position=page_index, container_id=book._id)]
          )
        page = page.update_collection(db_interface=db, user=get_user())
        page_storage_path = page.get_external_storage_path(db_interface=db)
        logging.debug(page_storage_path)

        input_filename = os.path.basename(uploaded_file.filename)
        logging.debug(input_filename)
        original_file_path = os.path.join(page_storage_path, "original__" + input_filename)
        if not os.path.exists(os.path.dirname(original_file_path)):
            os.makedirs(os.path.dirname(original_file_path))
        uploaded_file.save(original_file_path)

        image_file_name = "content.jpg"
        tmp_image = cv2.imread(original_file_path)
        cv2.imwrite(os.path.join(page_storage_path, image_file_name), tmp_image)

        image = Image.open(os.path.join(page_storage_path, image_file_name)).convert('RGB')
        working_filename = "content__resized_for_uniform_display.jpg"
        out = open(os.path.join(page_storage_path, working_filename), "w")
        img = DocImage.resize(image, (1920, 1080), False)
        img.save(out, "JPEG", quality=100)
        out.close()

        image = Image.open(join(page_storage_path, image_file_name)).convert('RGB')
        thumbnailname = "thumb.jpg"
        out = open(join(page_storage_path, thumbnailname), "w")
        img = DocImage.resize(image, (400, 400), True)
        img.save(out, "JPEG", quality=100)
        out.close()
    except:
      message = {
        "message": "Unexpected error while saving files: " + str(sys.exc_info()[0]),
        "details": traceback.format_exc()
      }
      logging.error(str(message))
      logging.error(traceback.format_exc())
      book_portion_node = common_data_containers.JsonObjectNode.from_details(content=book)
      logging.error("Rolling back and deleting the book!")
      book_portion_node.delete_in_collection(db_interface=db)
      return message, 419

    book_portion_node = common_data_containers.JsonObjectNode.from_details(content=book)
    book_portion_node.fill_descendents(db_interface=db)

    return book_portion_node.to_json_map(), 200

@api.route('/dbs/<string:db_id>/pages/<string:page_id>/annotations')
class AllPageAnnotationsHandler(flask_restplus.Resource):
  @api.doc(
    responses={404: 'id not found'})
  def get(self, page_id, db_id):
    """ Get all annotations (pre existing or automatically generated, using
    image segmentation) for this page image.

    :param page_id:
    :param db_id
    :return: A list of JsonObjectNode-s with annotations with the following structure.
      {"content": ImageAnnotation, "children": [JsonObjectNode with TextAnnotation_1]}
    """
    logging.info("page get by id = " + str(page_id))
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    page = common_data_containers.JsonObject.from_id(id=page_id, db_interface=db)
    if page is None:
      return "No such book portion id", 404
    else:
      page_image = DocImage.from_path(path=os.path.join(page.get_external_storage_path(db_interface=db), page.list_files(db_interface=db, suffix_pattern="content*")[0]))
      image_annotations = db.update_image_annotations(page=page, page_image=page_image)
      image_annotation_nodes = [common_data_containers.JsonObjectNode.from_details(content=annotation) for annotation in
                                image_annotations]
      for node in image_annotation_nodes:
        node.fill_descendents(db_interface=db)
      return common_data_containers.JsonObject.get_json_map_list(image_annotation_nodes), 200

# noinspection PyUnresolvedReferences,PyShadowingBuiltins
@api.route('/dbs/<string:db_id>/entities/<string:id>/targetters')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
@api.param('id', 'Hint: Get one from the JSON object returned by another GET call. ')
class EntityTargettersHandler(flask_restplus.Resource):
  get_parser = api.parser()
  get_parser.add_argument('depth', location='args', type=int, default=10,
                          help="Do you want sub-portions or sub-sub-portions or sub-sub-sub-portions etc..? Minimum 1.")
  get_parser.add_argument('targetter_class', location='args', type=str,
                          help="Example: BookPortion. See jsonClass.enum values in <a href=\"v1/schemas\"> schema</a> definitions.")
  get_parser.add_argument('filter_json', location='args', type=str,
                          help="A brief JSON string with property: value pairs. Currently unimplemented.")

  # noinspection PyShadowingBuiltins
  @api.expect(get_parser, validate=True)
  def get(self, db_id, id):
    """ Get all targetters for this entity.

    :param db_id:
    :param id:

    :return: A list of JsonObjectNode-s with targetters with the following structure.

      {"content": Annotation, "children": [JsonObjectNode with targetting Entity]}
    """
    logging.info("entity id = " + str(id))
    entity = common_data_containers.UllekhanamJsonObject()
    entity._id = str(id)
    args = self.get_parser.parse_args()
    logging.debug(args["filter_json"])
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    targetters = entity.get_targetting_entities(db_interface=db, entity_type=args["targetter_class"])
    targetter_nodes = [
      common_data_containers.JsonObjectNode.from_details(content=annotation)
      for annotation in targetters]
    for node in targetter_nodes:
      node.fill_descendents(db_interface=db, depth=args["depth"] - 1, entity_type=args["targetter_class"])
    return common_data_containers.JsonObject.get_json_map_list(targetter_nodes), 200


# noinspection PyUnresolvedReferences
@api.route('/dbs/<string:db_id>/entities/<string:id>')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
@api.param('id', 'Hint: Get one from the JSON object returned by another GET call. ')
class EntityHandler(flask_restplus.Resource):
  get_parser = api.parser()
  get_parser.add_argument('depth', location='args', type=int, default=1,
                          help="Do you want children or grandchildren or great grandchildren etc.. of this entity?")

  # noinspection PyShadowingBuiltins
  @api.doc(responses={404: 'id not found'})
  @api.expect(get_parser, validate=True)
  def get(self, db_id, id):
    """ Get any entity.

    :param db_id:
    :param id: String

    :return: Entity with descendents in a json tree like:

      {"content": EntityObj, "children": [JsonObjectNode with Child_1, JsonObjectNode with Child_2]}
    """
    args = self.get_parser.parse_args()
    logging.info("entity get by id = " + id)
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    entity = common_data_containers.JsonObject.from_id(id=id, db_interface=db)
    if entity is None:
      return "No such entity id", 404
    else:
      node = common_data_containers.JsonObjectNode.from_details(content=entity)
      node.fill_descendents(db_interface=db, depth=args['depth'])
      # pprint(binfo)
      return node.to_json_map(), 200


@api.route('/dbs/<string:db_id>/entities/<string:id>/files')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
@api.param('id', 'Hint: Get one from the JSON object returned by another GET call. ')
class EntityFileListHandler(flask_restplus.Resource):
  get_parser = api.parser()
  get_parser.add_argument('pattern', location='args', type=str, default="*",
                          help="Wildcard pattern for the file you want ot find.")

  # noinspection PyShadowingBuiltins
  @api.doc(responses={404: 'id not found'})
  @api.expect(get_parser, validate=True)
  def get(self, db_id, id):
    """ Get files associated with an entity.

    :param db_id:
    :param id: String

    :return: Entity with descendents in a json tree like:

      {"content": EntityObj, "children": [JsonObjectNode with Child_1, JsonObjectNode with Child_2]}
    """
    args = self.get_parser.parse_args()
    logging.info("entity get by id = " + id)
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    entity = common_data_containers.JsonObject.from_id(id=id, db_interface=db)
    if entity is None:
      return "No such entity id", 404
    else:
      return entity.list_files(db_interface=db, suffix_pattern=args["pattern"]), 200


@api.route('/dbs/<string:db_id>/entities/<string:id>/files/<string:file_name>')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
@api.param('id', 'Hint: Get one from the JSON object returned by another GET call. ')
@api.param('file_name', 'Hint: Get one from the file list returned by another GET call. ')
class EntityFileHandler(flask_restplus.Resource):
  # noinspection PyShadowingBuiltins
  @api.doc(responses={404: 'id not found'})
  @api.representation('image/*')
  def get(self, db_id, id, file_name):
    """ Get files associated with an entity.

    :param db_id:
    :param id: String
    :param file_name: String

    :return: Entity with descendents in a json tree like:

      {"content": EntityObj, "children": [JsonObjectNode with Child_1, JsonObjectNode with Child_2]}
    """
    logging.info("entity get by id = " + id)
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    entity = common_data_containers.JsonObject.from_id(id=id, db_interface=db)
    if entity is None:
      return "No such entity id", 404
    else:
      from flask import send_from_directory
      return send_from_directory(directory=entity.get_external_storage_path(db_interface=db), filename=file_name)


@api.route('/dbs/<string:db_id>/entities')
@api.param('db_id', 'Hint: Get one from the JSON object returned by another GET call. ')
class EntityListHandler(flask_restplus.Resource):
  # input_node = api.model('JsonObjectNode', common_data_containers.JsonObjectNode.schema)

  get_parser = api.parser()
  get_parser.add_argument('filter_json', location='args', type=str,
                          help="A brief JSON string with property: value pairs. Currently unimplemented.")

  @api.expect(get_parser, validate=True)
  def get(self, db_id):
    """ Get all matching entities- Currently unimplemented."""
    args = self.get_parser.parse_args()
    logging.debug(args["filter_json"])
    return "NOT IMPLEMENTED!", 401

  post_parser = api.parser()
  post_parser.add_argument('jsonStr', location='json')

  # TODO: The below fails. Await response on https://github.com/noirbizarre/flask-restplus/issues/194#issuecomment-284703984 .
  # @api.expect(json_node_model, validate=False)

  @api.expect(post_parser, validate=False)
  @api.doc(responses={
    200: 'Update/insert success.',
    401: 'Unauthorized. Use ../auth/v1/oauth_login/google to login and request access at https://github.com/vedavaapi/vedavaapi_py_api .',
    417: 'JSON schema validation error.',
    418: "Target entity class validation error."
  })
  def post(self, db_id):
    """ Add some trees of entities. (You **cannot** add a DAG graph of nodes in one shot - you'll need multiple calls.)
    
    input json:

      A list of JsonObjectNode-s with entities with the following structure.

      {"content": Annotation or BookPortion, "children": [JsonObjectNode with child Annotation or BookPortion]}    

    :return: 

      Same as the input trees, with id-s.
    """
    logging.info(str(request.json))
    if not check_permission(db_name=db_id):
      return "", 401
    nodes = common_data_containers.JsonObject.make_from_dict_list(request.json)
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    for node in nodes:
      from jsonschema import ValidationError
      # noinspection PyUnusedLocal,PyUnusedLocal
      try:
        node.update_collection(db_interface=db, user=get_user())
      except ValidationError as e:
        message = {
          "message": "Some input object does not fit the schema.",
          "exception_dump": (traceback.format_exc())
        }
        return message, 417
      except common_data_containers.TargetValidationError as e:
        message = {
          "message": "Target validation failed.",
          "exception_dump": (traceback.format_exc())
        }
        return message, 418
    return common_data_containers.JsonObject.get_json_map_list(nodes), 200

  @api.expect(post_parser, validate=False)
  @api.doc(responses={
    200: 'Delete success.',
    401: 'Unauthorized. Use /auth/v1/oauth_login/google to login and request access at https://github.com/vedavaapi/vedavaapi_py_api .',
  })
  def delete(self, db_id):
    """ Delete trees of entities.
    
    input json:

      A list of JsonObjectNode-s with entities with the following structure.

      {"content": Annotation or BookPortion, "children": [JsonObjectNode with child Annotation or BookPortion]}    

    :return: Empty.
    """
    if not check_permission(db_name=db_id):
      return "", 401
    nodes = common_data_containers.JsonObject.make_from_dict_list(request.json)
    db = get_db(db_name_frontend=db_id)
    if db is None:
      return "No such db id", 404
    for node in nodes:
      node.delete_in_collection(db_interface=db, user=get_user())
    return {}, 200


# noinspection PyMethodMayBeStatic
@api.route('/schemas')
class SchemaListHandler(flask_restplus.Resource):
  def get(self):
    """Just list the schemas."""
    from sanskrit_data.schema import common, books, ullekhanam
    logging.debug(common.get_schemas(common))
    schemas = common.get_schemas(common)
    schemas.update(common.get_schemas(books))
    schemas.update(common.get_schemas(ullekhanam))
    return schemas, 200

__all__ = ["api_blueprint"]
