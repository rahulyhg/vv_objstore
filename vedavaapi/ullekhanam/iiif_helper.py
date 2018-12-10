from collections import OrderedDict

from sanskrit_ld.helpers import db_helper
from sanskrit_ld.schema import JsonObject

from vedavaapi.iiif_image.loris.resolver import ServiceFSHelper
from vedavaapi.iiif_presentation.prezed.sevices_helper import ServicePreziInterface


def myservice():
    from . import VedavaapiUllekhanam
    return VedavaapiUllekhanam.instance


class UllekhanamPreziInterface(ServicePreziInterface):

    service_name = 'ullekhanam'

    def __init__(self, repo_name):
        super(UllekhanamPreziInterface, self).__init__(repo_name)
        self.colln = myservice().colln(self.repo_name)

    def collection_details(self, collection_id):
        # meta, objects
        # TODO should implement collections
        if collection_id != 'books':
            return None
        return self._default_collection_details()

    def object_details(self, object_id):
        # meta, default_sequence_id, sequence_ids
        obj = db_helper.read_by_id(self.colln, object_id)
        obj_meta = {
            "metadata": obj.get("metadata", []),
        }
        obj_meta.update({
            "label": obj.get('title', {}).get('chars', object_id),
        })
        self._index_metadata(obj_meta)
        return {
            "meta": obj_meta,
            "default_sequence_id": "default",
            "sequence_ids": []
        }

    def sequence_details(self, object_id, sequence_id):
        # meta, canvases
        # TODO should implement sequences
        if sequence_id != 'default':
            return None
        return self._default_sequence_details(object_id)

    def canvas_details(self, sequence_id, canvas_id):
        # meta, image_id or (image_ids and dimensions)
        # TODO optimize url
        spr = db_helper.read_by_id(self.colln, canvas_id)
        label = spr.get('label', spr.get('jsonClassLabel:', 'page:'))  # TODO
        meta = {
            "metadata": spr.get("metadata", [])
        }
        meta.update({
            'label': label
        })

        source_images = db_helper.files(self.colln, canvas_id)
        source_image_ids = [file['_id'] for file in source_images]
        self._index_metadata(meta)
        return {
            "meta": meta,
            "image_id": source_image_ids[0] if len(source_image_ids) else None
        }

    def _default_collection_details(self):
        # until we implement collections, and ways to populate them,
        # default one will be dynamically generated with all books
        ops = OrderedDict([
            ('sort', [[["title.chars", 1]]])
        ])
        books = db_helper.read_and_do(self.colln, {"jsonClass": "BookPortion"}, ops=ops, fields=['_id', 'title.chars'])

        return {
            "meta": {
                "label": "books"
            },
            "object_ids": [book['_id'] for book in books]
        }

    def _default_sequence_details(self, object_id):
        pages = db_helper.read_and_do(
            self.colln, {"jsonClass": "Page", "source": object_id}, ops=OrderedDict(), fields=['_id']
        )

        return {
            "canvas_ids": [page['_id'] for page in pages]
        }

    def _index_metadata(self, repr):
        if 'metadata' in repr:
            repr['metadata'] = dict([(mi['label'], mi['value']) for mi in repr['metadata']])


class UllekhanamFSHelper(ServiceFSHelper):

    def __init__(self, repo_name):
        super(UllekhanamFSHelper, self).__init__(repo_name)

        self.colln = myservice().colln(self.repo_name)

    def resolve_to_absolute_path(self, file_anno_id):
        file_anno = JsonObject.make_from_dict(db_helper.read_by_id(self.colln, file_anno_id))
        if file_anno is None:
            return None

        custodian_resource_id = file_anno.target
        file_path_in_resource_scope = file_anno.body.path
        file_path = myservice().resource_file_path(
            self.repo_name, custodian_resource_id, file_path_in_resource_scope)
        return file_path
