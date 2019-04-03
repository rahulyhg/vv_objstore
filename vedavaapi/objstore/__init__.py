import logging

import os

from vedavaapi.objectdb.mydb import MyDbCollection
from vedavaapi.common import VedavaapiService, OrgHandler

from .helpers.iiif_helper import ObjstoreFSInterface, ObjstoreIIIFModelInterface
from .helpers.bootstrap_helper import bootstrap_initial_resources


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)


class ObjstoreOrgHandler(OrgHandler):
    def __init__(self, service, org_name):
        super(ObjstoreOrgHandler, self).__init__(service, org_name)

        self.objstore_db_config = self.dbs_config['objstore_db']
        self.objstore_db = self.store.db(self.objstore_db_config['name'])
        self.objstore_colln = self.objstore_db.get_collection(
            self.objstore_db_config['collections']['objstore']
        )

        self.root_dir_path = self.store.file_store_path(
            file_store_type='data',
            base_path=''
        )
        self.initial_agents = None

    def get_iiif_model_interface(self):
        if not hasattr(self, 'iiif_prezi_interface'):
            self.iiif_model_interface = ObjstoreIIIFModelInterface(self.org_name)
        return self.iiif_model_interface

    def get_fs_interface(self):
        if not hasattr(self, 'files_helper'):
            self.fs_interface = ObjstoreFSInterface(self.org_name)
        return self.fs_interface

    def data_dir_path(self):
        return self.store.file_store_path(
            file_store_type='data',
            base_path=''
        )

    def initialize(self):
        self.initial_resources = bootstrap_initial_resources(self.objstore_colln, self.org_name, self.org_config)


class VedavaapiObjstore(VedavaapiService):

    instance = None  # type: VedavaapiObjstore

    dependency_services = ['accounts']
    org_handler_class = ObjstoreOrgHandler

    title = "Vedavaapi Object Store"
    description = "Object store api"

    def __init__(self, registry, name, conf):
        super(VedavaapiObjstore, self).__init__(registry, name, conf)
        self.vvstore = self.registry.lookup("store")

    def colln(self, org_name):
        return self.get_org(org_name).objstore_colln  # type: MyDbCollection

    def get_accounts_api_config(self, org_name):
        return self.get_org(org_name).accounts_api_config

    def get_initial_agents(self, org_name):
        return self.get_org(org_name).initial_agents

    def set_initial_agents(self, org_name, initial_agents):
        self.get_org(org_name).initial_agents = initial_agents

    def data_dir_path(self, org_name):
        return self.get_org(org_name).data_dir_path()

    def root_dir_path(self, org_name):
        return self.get_org(org_name).root_dir_path

    def iiif_model_interface(self, org_name):
        return self.get_org(org_name).get_iiif_model_interface()

    def fs_interface(self, org_name):
        return self.get_org(org_name).get_fs_interface()
