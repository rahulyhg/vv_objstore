"""
A general API to access and annotate a text corpus.

api_v1 is the main submodule.
"""

import logging
import sys
import os

# Essential for depickling to work.
from sanskrit_data.schema import *  # pylint: disable=unused-import.
from sanskrit_data.schema.books import BookPortion
from sanskrit_data.schema.ullekhanam import TextAnnotation

from vedavaapi.common import *

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)

# Dummy usage.
# logging.debug("So that depickling works well, we imported: " + str([common, ullekhanam, books, users]))

from vedavaapi.common import VedavaapiService

ServiceObj = None


class VedavaapiUllekhanam(VedavaapiService):
    dependency_services = ['store', 'users']

    def __init__(self, registry, name, conf):
        super(VedavaapiUllekhanam, self).__init__(registry, name, conf)
        self.vvstore = VedavaapiServices.lookup("store")
        import_blueprints_after_service_is_ready(self)

    def setup(self):
        db_name_end = self.config.get('ullekhanam_db')
        file_store_base_path = self.config.get('file_store')
        self.dbs_map = self.vvstore.db_interfaces_from_all_repos(
            db_name_end=db_name_end,
            db_name_frontend='ullekhanam',
            file_store_base_path=file_store_base_path,
            db_type="ullekhanam_db"
        )
        for repo, db in self.dbs_map.items():
            BookPortion.add_indexes(db_interface=db)
            TextAnnotation.add_indexes(db_interface=db)


    def reset(self):
        db_name_end = self.config.get('ullekhanam_db')
        file_store_base_path = self.config.get('file_store')
        self.vvstore.delete_db_in_all_repos(
            db_name_end=db_name_end,
            delete_external_file_store=True,
            file_store_base_path=file_store_base_path
        )

    def get_db(self, repo_id):
        return self.dbs_map.get(repo_id, None)


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
