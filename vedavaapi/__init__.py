"""
Introduction
============

Python based Web API's for the <vedavaapi.org> project.

Usage
=====

Setup
-----

-  Get the code and install various necessary python 3 modules.

   -  Refer to list in setup.py.
   -  Possibly easy way (untested):
      ``sudo pip3 install --target=/home/samskritam/ git+https://github.com/vedavaapi/vedavaapi_py_api@master``
   -

      To get the latest development snapshot, you may need to install the modules ``sanskrit_data`` and ``docimage`` directly from the git repositories. Example:
          ``sudo pip3 install git+https://github.com/vedavaapi/sanskrit_data@master -U``
          or ``cd sasnkrit_data; sudo pip3 install -e .``

-  Data setup: Grant the account running run.py authority to write in
   /opt/vedavaapi/.

   -  ``sudo mkdir /opt/vedavaapi/; sudo mkdir /opt/vedavaapi/data; sudo chmod a+rwx /opt/vedavaapi``
   -  ``rm -Rf /opt/vedavaapi/data/books/ullekhanam_test_v2``
   -  ``cp -R ~/vedavaapi_py_api/textract-example-repo/books_v2 /opt/vedavaapi/data/books/ullekhanam_test_v2``

-  Install mongodb 3.4.
-  [Optional, deprecated alternative] Install and set up couchdb:

   -  Consider using `our cookbook`_ with chef for easily installing
      couchdb with full text indexing enabled.
   -  Alter the local.ini file to provide write permissions to the
      admin.

-  Set up the ``vedavaapi_py_api/server_config_local.config`` file based
   on ``vedavaapi_py_api/server_config_template.config``. The database
   details should match your database setup!
-  For further details of setting this app up in the context of the
   vedavaapi server, see `vedavaapi_servercfg`_ .

Running
-------

-  Launch server: run.py.
-  General maintenance and deployment instructions - see
   `vedavaapi_servercfg`_.

Diagnostics
~~~~~~~~~~~

-  List routes: /sitemap on your browser.

REST API docs:
--------------

-  Generally, just try the /docs/ path under the appropriate module.
   Example: `here`_ .
-  These links may be provided in various module-specific sections
   below.

.. _our cookbook: https://github.com/vedavaapi/vedavaapi-chef
.. _vedavaapi_servercfg: https://github.com/vedavaapi/vedavaapi-misc
.. _here: http://api.vedavaapi.org/py/textract/docs
"""
__path__ = __import__('pkgutil').extend_path(__path__, __name__)
