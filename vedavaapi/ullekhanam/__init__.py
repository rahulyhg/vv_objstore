import logging

import os

from vedavaapi.objectdb.mydb import MyDbCollection
from vedavaapi.common import VedavaapiService, ServiceRepo

from .iiif_helper import UllekhanamFSHelper, UllekhanamPreziInterface


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)


class UllekhanamRepo(ServiceRepo):
    def __init__(self, service, repo_name):
        super(UllekhanamRepo, self).__init__(service, repo_name)

        self.ullekhanam_db_config = self.dbs_config['ullekhanam_db']
        self.books_base_path = self.service.config.get('books_base_path')

        self.ullekhanam_db = self.db(self.ullekhanam_db_config['name'])

        self.ullekhanam_colln = self.ullekhanam_db.get_collection(
            self.ullekhanam_db_config['collections']['ullekhanam']
        )

        self.root_dir_path = self.store.file_store_path(
            repo_name=self.repo_name,
            service_name=self.service.name,
            file_store_type='data',
            base_path=''
        )

    def prezi_interface(self):
        if not hasattr(self, 'iiif_prezi_interface'):
            self.iiif_prezi_interface = UllekhanamPreziInterface(self.repo_name)
        return self.iiif_prezi_interface

    def fs_helper(self):
        if not hasattr(self, 'files_helper'):
            self.files_helper = UllekhanamFSHelper(self.repo_name)
        return self.files_helper

    def resource_dir_path(self, resource_id):
        return self.store.file_store_path(
            repo_name=self.repo_name,
            service_name=self.service.name,
            file_store_type='data',
            base_path=resource_id
        )

    def resource_file_path(self, resource_id, file_name):
        base_path = os.path.join(resource_id.lstrip('/'), file_name.lstrip('/'))
        return self.store.file_store_path(
            repo_name=self.repo_name,
            service_name=self.service.name,
            file_store_type='data',
            base_path=base_path
        )

    def initialize(self):
        pass


class VedavaapiUllekhanam(VedavaapiService):

    instance = None  # type: VedavaapiUllekhanam

    dependency_services = ['store', 'users']
    svc_repo_class = UllekhanamRepo

    title = "Vedavaapi Ullekhanam"
    description = "Multi-layered annotator for Indic documents"

    def __init__(self, registry, name, conf):
        super(VedavaapiUllekhanam, self).__init__(registry, name, conf)
        self.vvstore = self.registry.lookup("store")

    def colln(self, repo_name):
        return self.get_repo(repo_name).ullekhanam_colln  # type: MyDbCollection

    def root_dir_path(self, repo_name):
        return self.get_repo(repo_name).root_dir_path

    def resource_dir_path(self, repo_name, resource_id):
        return self.get_repo(repo_name).resource_dir_path(resource_id)

    def resource_file_path(self, repo_name, resource_id, file_name):
        return self.get_repo(repo_name).resource_file_path(resource_id, file_name)

    def prezi_interface(self, repo_name):
        return self.get_repo(repo_name).prezi_interface()

    def fs_helper(self, repo_name):
        return self.get_repo(repo_name).fs_helper()
