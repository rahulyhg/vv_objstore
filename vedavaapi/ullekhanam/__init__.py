"""
A general API to access and annotate a text corpus.

api_v1 is the main submodule.
"""

import logging

# Essential for depickling to work.
from sanskrit_data.schema import *  # pylint: disable=unused-import.
from sanskrit_data.schema.books import BookPortion
from sanskrit_data.schema.ullekhanam import TextAnnotation

from vedavaapi.common import VedavaapiService, ServiceRepoInterface

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)

# Dummy usage.
# logging.debug("So that depickling works well, we imported: " + str([common, ullekhanam, books, users]))

ServiceObj = None


class UllekhanamRepoInterface(ServiceRepoInterface):
    def __init__(self, service, repo_name):
        super(UllekhanamRepoInterface, self).__init__(service, repo_name)

        self.db_name_suffix = self.service.config.get('ullekhanam_db')
        self.books_base_path = self.service.config.get('books_base_path')

        self.ullekhanam_db = self.db(
            db_name_suffix=self.db_name_suffix,
            db_type='ullekhanam_db'
        )
        self.books_path = self.store.file_store_path(
            repo_name= self.repo_name,
            service_name= self.service.name,
            file_store_type= 'data',
            base_path = self.books_base_path
        )  # dirs will get created automatically

    def initialize(self):
        BookPortion.add_indexes(self.ullekhanam_db)
        TextAnnotation.add_indexes(self.ullekhanam_db)

    def reset(self):
        self.store.delete_db(
            repo_name=self.repo_name,
            db_name_suffix=self.db_name_suffix
        )
        self.store.delete_data(self.repo_name, self.service.name)


class VedavaapiUllekhanam(VedavaapiService):
    dependency_services = ['store', 'users']
    repo_interface_class = UllekhanamRepoInterface

    def __init__(self, registry, name, conf):
        super(VedavaapiUllekhanam, self).__init__(registry, name, conf)
        self.vvstore = self.registry.lookup("store")
        import_blueprints_after_service_is_ready(self)

    def db(self, repo_name):
        return self.get_repo(repo_name).ullekhanam_db

    def books_path(self, repo_name):
        return self.get_repo(repo_name).books_path


def myservice():
    return ServiceObj

def get_store():
    return myservice().vvstore


api_blueprints = []


def import_blueprints_after_service_is_ready(service_obj):
    global ServiceObj
    ServiceObj = service_obj
    from .api_v1 import api_blueprint as apiv1_blueprint
    api_blueprints.append(apiv1_blueprint)
