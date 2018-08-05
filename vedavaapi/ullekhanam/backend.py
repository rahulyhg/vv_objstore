"""
Sets up database with add_db() and getdb().
"""

import logging
import os

from sanskrit_data.schema.books import BookPortion
from sanskrit_data.schema.ullekhanam import TextAnnotation


dbs = {}


def add_db(db, reimport=False):
  logging.info("Initializing database")
  logging.info(db.__class__)
  ullekhanam_db = db

  ## General indices (corresponds to schema defined in schema.common).
  # Not really required since BookPortion index creation automatically includes the below.
  # JsonObject.add_indexes(db_interface=ullekhanam_db)
  # UllekhanamJsonObject.add_indexes(db_interface=ullekhanam_db)

  ## Book portion indices (corresponds to schema defined in schema.books).
  # Appropriate index use confirmed: https://trello.com/c/CHKgDABv/117-mongodb-index-array-of-array
  BookPortion.add_indexes(db_interface=ullekhanam_db)

  ## Annotation indices (corresponds to schema defined in schema.ullekhanam).
  TextAnnotation.add_indexes(db_interface=ullekhanam_db)

  global dbs
  dbs[db.db_name_frontend] = ullekhanam_db

  if reimport:
    ullekhanam_db.import_all(rootdir=db.external_file_store)


def get_db(db_name_frontend="ullekhanam"):
  if db_name_frontend in dbs:
    return dbs[db_name_frontend]
  else:
    return None


def get_file_store(db_name_frontend="ullekhanam"):
  if db_name_frontend in dbs:
    return dbs[db_name_frontend].external_file_store
  else:
    return None

class ScannedBook(object):
    def __init__(self):
        pass
