import flask_restplus
from flask import Blueprint
from .. import myservice

api_blueprint_v1 = Blueprint(myservice().name + '_v1', __name__)

api = flask_restplus.Api(
    app=api_blueprint_v1,
    version='1.0',
    prefix='/v1',
    title=myservice().title,
    description='For detailed intro and to report issues: see <a '
                'href="https://github.com/vedavaapi/vedavaapi_py_api">here</a>. '
                'For using some API, you need to log in using <a href="../auth/v1/oauth_login/google">google</a>.'
    # We are not linking to  <a href="v1/schemas"> below since it results in an error on Chrome. See 
    # https://github.com/vedavaapi/vedavaapi_py_api/issues/3 
                'For a list of JSON schema-s this API uses (referred to by name in docs) see the schemas API '
                'below.</a>. '
                'Please also see videos <a href="https://www.youtube.com/playlist?list'
                '=PL63uIhJxWbghuZDlqwRLpPoPPFDNQppR6">here</a>, '
                '<a href="https://docs.google.com/presentation/d/1Wx1rxf5W5VpvSS4oGkGpp28WPPM57CUx41dGHC4ed80/edit'
                '">slides</a>,  <a href="http://sanskrit-data.readthedocs.io/en/latest/sanskrit_data_schema.html'
                '#class-diagram" > class diagram </a> as well as the sources ( <a '
                'href="http://sanskrit-data.readthedocs.io/en/latest/_modules/sanskrit_data/schema/books.html'
                '#BookPortion">example</a> ) - It might help you understand the schema more easily.<BR> '
                'A list of REST and non-REST API routes avalilable on this server: <a href="../sitemap">sitemap</a>. ',
    doc='/v1'
)

from . import rest
