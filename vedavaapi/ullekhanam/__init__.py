"""
A general API to access and annotate a text corpus.

api_v1 is the main submodule.
"""

import logging

# Essential for depickling to work.
from sanskrit_data.schema import *  # pylint: disable=unused-import.
from sanskrit_data.schema.books import BookPortion
from sanskrit_data.schema.ullekhanam import TextAnnotation

from vedavaapi.common import VedavaapiService, ServiceRepo

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)

# Dummy usage.
# logging.debug("So that depickling works well, we imported: " + str([common, ullekhanam, books, users]))


class UllekhanamRepo(ServiceRepo):
    def __init__(self, service, repo_name):
        super(UllekhanamRepo, self).__init__(service, repo_name)

        self.ullekhanam_db_config = self.dbs_config['ullekhanam_db']
        self.books_base_path = self.service.config.get('books_base_path')

        self.ullekhanam_db = self.db(self.ullekhanam_db_config['name'])
        self.ullekhanam_colln = self.ullekhanam_db.get_collection(self.ullekhanam_db_config['collections']['ullekhanam'])

        self.books_path = self.store.file_store_path(
            repo_name= self.repo_name,
            service_name= self.service.name,
            file_store_type= 'data',
            base_path = self.books_base_path
        )  # dirs will get created automatically

    def initialize(self):
        BookPortion.add_indexes(self.ullekhanam_colln)
        TextAnnotation.add_indexes(self.ullekhanam_colln)


class VedavaapiUllekhanam(VedavaapiService):

    instance = None

    dependency_services = ['store', 'users']
    svc_repo_class = UllekhanamRepo

    title = "Vedavaapi Ullekhanam"
    description = "Multi-layered annotator for Indic documents"

    def __init__(self, registry, name, conf):
        super(VedavaapiUllekhanam, self).__init__(registry, name, conf)
        self.vvstore = self.registry.lookup("store")

    def colln(self, repo_name):
        return self.get_repo(repo_name).ullekhanam_colln

    def books_path(self, repo_name):
        return self.get_repo(repo_name).books_path
