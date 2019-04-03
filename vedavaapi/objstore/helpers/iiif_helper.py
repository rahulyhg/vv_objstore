from vedavaapi.iiif_presentation.prezed.iiif_model_helper import VedavaapiIIIFModelInterface
from vedavaapi.iiif_image.loris.resolver import VedavaapiFSInterface


def myservice():
    from .. import VedavaapiObjstore
    return VedavaapiObjstore.instance


class ObjstoreIIIFModelInterface(VedavaapiIIIFModelInterface):

    service_name = 'objstore'

    def __init__(self, org_name):

        colln = myservice().colln(org_name)
        super(ObjstoreIIIFModelInterface, self).__init__(org_name, colln)


class ObjstoreFSInterface(VedavaapiFSInterface):

    service_name = 'objstore'

    def __init__(self, org_name):
        colln = myservice().colln(org_name)
        data_dir_path = myservice().data_dir_path(org_name)
        super(ObjstoreFSInterface, self).__init__(org_name, colln, data_dir_path)
