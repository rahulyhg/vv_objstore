from collections import OrderedDict

from sanskrit_ld.schema import JsonObject
from vedavaapi.objectdb.mydb import MyDbCollection
from vedavaapi.objectdb import objstore_helper

from vedavaapi.iiif_image.loris.resolver import ServiceFSHelper
from vedavaapi.iiif_presentation.prezed.sevices_helper import ServicePreziInterface


def myservice():
    from .. import VedavaapiObjstore
    return VedavaapiObjstore.instance


class ObjstorePreziInterface(ServicePreziInterface):

    service_name = 'objstore'

    def __init__(self, org_name):
        super(ObjstorePreziInterface, self).__init__(org_name)
        self.colln = myservice().colln(self.org_name)  # type: MyDbCollection

    def collection_details(self, collection_id):
        # meta, objects
        if collection_id == 'books':
            # deprecated
            return self._default_collection_details()

        collection = self.colln.find_one(
            {"jsonClass": "Library", "_id": collection_id}, projection={"permissions": 0})
        if collection is None:
            return None

        sub_collection_ids = [
            sc['_id']
            for sc in self.colln.find({"jsonClass": "Library", "source": collection_id}, projection={"_id": 1})]
        manifests_ids = [
            mn['_id']
            for mn in self.colln.find({"jsonClass": "BookPortion", "source": collection_id}, projection={"_id": 1})]

        return {
            "meta": {"label": collection.get('name', collection_id)},
            "sub_collection_ids": sub_collection_ids,
            "object_ids": manifests_ids
        }

    def object_details(self, object_id):
        # meta, default_sequence_id, sequence_ids
        obj = self.colln.get(object_id, projection={"permissions": 0})
        if obj is None:
            return None
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
        spr = self.colln.get(canvas_id, projection={"permissions": 0})
        if spr is None:
            return None
        label = spr.get('label', spr.get('jsonClassLabel:', 'page:'))  # TODO
        meta = {
            "metadata": spr.get("metadata", [])
        }
        meta.update({
            'label': label
        })

        source_image = self.colln.find_one(objstore_helper.files_selector_doc(canvas_id), projection={"_id": 1})
        source_image_id = source_image['_id'] if source_image else None
        self._index_metadata(meta)
        return {
            "meta": meta,
            "image_id": source_image_id
        }

    def _default_collection_details(self):
        # until we implement collections, and ways to populate them,
        # default one will be dynamically generated with all books
        ops = OrderedDict([
            ('sort', [[["title.chars", 1]]])
        ])
        books = self.colln.find_and_do({"jsonClass": "BookPortion"}, ops=ops, projection={'_id': 1, 'title.chars': 1})

        return {
            "meta": {
                "label": "books"
            },
            "object_ids": [book['_id'] for book in books]
        }

    def _default_sequence_details(self, object_id):
        pages = self.colln.find_and_do(
            {"jsonClass": "Page", "source": object_id}, ops=OrderedDict(), projection={'_id': 1}
        )

        return {
            "canvas_ids": [page['_id'] for page in pages]
        }

    # noinspection PyMethodMayBeStatic
    def _index_metadata(self, repr):
        if 'metadata' in repr:
            repr['metadata'] = dict([(mi['label'], mi['value']) for mi in repr['metadata']])


class ObjstoreFSHelper(ServiceFSHelper):

    def __init__(self, org_name):
        super(ObjstoreFSHelper, self).__init__(org_name)

        self.colln = myservice().colln(self.org_name)

    def resolve_to_absolute_path(self, file_anno_id):
        file_anno = JsonObject.make_from_dict(self.colln.get(file_anno_id, projection={"permissions": 0}))
        if file_anno is None:
            return None

        custodian_resource_id = file_anno.target
        file_path_in_resource_scope = file_anno.body.path
        file_path = myservice().resource_file_path(
            self.org_name, custodian_resource_id, file_path_in_resource_scope)
        return file_path
