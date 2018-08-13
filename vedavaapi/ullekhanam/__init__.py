"""
A general API to access and annotate a text corpus.

api_v1 is the main submodule.
"""

import logging
import sys
import os

# Essential for depickling to work.
from sanskrit_data.schema import *  # pylint: disable=unused-import.
from .backend import add_db
from vedavaapi.common import *

logging.basicConfig(
  level=logging.INFO,
  format="%(levelname)s: %(asctime)s {%(filename)s:%(lineno)d}: %(message)s "
)

# Dummy usage.
#logging.debug("So that depickling works well, we imported: " + str([common, ullekhanam, books, users]))

from vedavaapi.common import VedavaapiService

ServiceObj = None

class VedavaapiUllekhanam(VedavaapiService):
    dependency_services = ['store']

    def __init__(self, registry, name, conf):
        super(VedavaapiUllekhanam, self).__init__(registry, name, conf)
        self.vvstore = VedavaapiServices.lookup("store")
        import_blueprints_after_service_is_ready(self)
        
    def setup(self):
        for db_details in self.config["ullekhanam_dbs"]:
            add_db(db=self.vvstore.client.get_database_interface(db_name_backend=db_details["backend_id"],
            db_name_frontend=db_details["frontend_id"],
            external_file_store=db_details.get("file_store"), db_type="ullekhanam_db"), reimport=False)

    def reset(self):
        for db_details in self.config["ullekhanam_dbs"]:
            logging.info("Deleting database/collection " + db_details["backend_id"])
            self.vvstore.client.delete_database(db_details["backend_id"])
            if "file_store" in db_details:
                try:
                    os.system("rm -rf " + db_details["file_store"])
                except Exception as e:
                    logging.error("Error removing " + db_details["file_store"]+": "+ e)

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


