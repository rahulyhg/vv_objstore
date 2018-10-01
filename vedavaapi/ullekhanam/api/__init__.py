import os

from sanskrit_data.schema import common
from vedavaapi.common.api_common import get_repo

from .. import VedavaapiUllekhanam


def myservice():
    return VedavaapiUllekhanam.instance


# methods acessing db
def get_colln():
    repo_name = get_repo()
    return myservice().colln(repo_name)

def list_books(colln):
    return [common.JsonObject.make_from_dict(input_dict=book) for book in colln.find({"portion_class": "book"})]

# methods accessing book_store
def books_store_path(base_path):
    repo_name = get_repo()
    return os.path.join(myservice().books_path(repo_name), base_path)


def page_dir_path(page):
    return books_store_path(page._id)


def list_files(base_path, suffix_pattern):
    return myservice().vvstore.list_files(
        books_store_path(base_path),
        suffix_pattern
    )


def list_files_under_entity(entity, suffix_pattern):
    return list_files(entity._id, suffix_pattern)


# importing blueprints
from .v1 import api_blueprint_v1
