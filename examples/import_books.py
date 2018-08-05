import requests
from sys import argv
import sys, getopt
import os
import json
import re
sys.path.append('..')
from sanskrit_data.schema.common import JsonObject, JsonObjectNode, DataSource
from sanskrit_data.schema.users import *
from sanskrit_data.schema.ullekhanam import *
from sanskrit_data.schema.books import *
from vedavaapi.client import VedavaapiClient, DotDict, print_dict

def import_books(rootdir):
    logging.info("Importing books into database from " + rootdir)
    mybooks = []
    for root, directories, filenames in os.walk(rootdir):
      for filename in filenames: 
        if not re.search("book.json$", os.path.basename(filename)):
            continue
            
        f = os.path.join(root,filename)
        logging.info("    " + f)
        (bookdir, bookpath) = os.path.split(f)
        with open(f) as fh:
            try:
                b = json.loads(fh.read())
            except Exception as e:
                print("Error reading ",f, ": ", e)
                continue

        # Create BookPortion objects for all pages
        pagenum = 0
        pages = []
        files_to_upload = []
        for p in b["pages"]:
            pagenum = pagenum + 1
            fname = p["fname"]
            #files_to_upload.append(('files', (fname, open(os.path.join(bookdir, fname), 'rb'))))

            pg_target = BookPositionTarget.from_details(position=pagenum, container_id='undefined')
            page = BookPortion.from_details("", path=fname, portion_class='page', 
                    base_data='image', 
                    targets=[pg_target])
            pages.append(JsonObjectNode.from_details(content=page))

        authors = []
        for a in b["author"].split(','):
            if a:
                authors.append(NamedEntity.from_name_string(a))

        # Create a BookPortion object for the book and add pages as children
        book = BookPortion.from_details(b["title"], authors=authors, \
                base_data='image', portion_class="book", path=bookdir, \
                source=DataSource.from_details(source_type="user_supplied", id="book_importer"))

        booknode = JsonObjectNode.from_details(content=book, children=pages)
        yield booknode

(cmddir, cmdname) = os.path.split(__file__)

def usage():
    print(cmdname + " [-r] [-u <username>:<password>] [-d <dbname>] -s <serverurl> <books_rootdir>")
    exit(1)

def main(argv):
    Parms = DotDict({
        'reset' : False,
        'dbgFlag' : True,
        'server_baseurl' : '',
        'auth' : DotDict({'user' : 'vedavaapiAdmin', 'passwd' : '@utoDump1'}),
                    'dbname' : 'ullekhanam_test' })

    try:
        opts, args = getopt.getopt(argv, "hru:d:s:", ["url="])
    except getopt.GetoptError:
        logging.info("Error in command line: ", getopt.GetoptError)
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-r", "--reset"):
            Parms.reset = True
        elif opt in ("-u", "--auth"):
            Parms.auth = DotDict(dict(zip(('user', 'passwd'), arg.split(':'))))
            print Parms.auth
        elif opt in ("-d", "--db"):
            Parms.dbname = arg
        elif opt in ("-s", "--serverurl"):
            logging.info("server url = ", arg)
            Parms.server_baseurl = arg
        else:
            logging.info("Unknown parameter: ", opt)
            usage()

    if not Parms.server_baseurl:
        logging.info("Error: Supply server URL via -s.")
        usage()
    if not args:
        logging.info("Error: Missing book path to import...")
        usage()

    vvclient = VedavaapiClient(Parms.server_baseurl)
    if not vvclient.authenticate(Parms.auth):
        sys.exit(1)

    for path in args:
        for book in import_books(path):
            pages = []
            for page in book.children:
                pages.append(('in_files', \
                    open(os.path.join(book.content.path, page.content.path), 'rb')))
            #print_dict(book.content.to_json_map())
            r = vvclient.post("ullekhanam/v1/dbs/{}/books".format(Parms.dbname), parms={'book_json' : json.dumps(book.content.to_json_map())}, files=pages)
            if not r:
                sys.exit(1)
            book_json = json.loads(r.text)
            book = JsonObject.make_from_dict(book_json["content"])
            #print_dict(book_json['content'])
            url = "ullekhanam/v1/dbs/{}/entities/{}".format(Parms.dbname,
                book._id)

            r = vvclient.get(url, {'depth' : 1})
            if not r:
                logging.error("Error: invoking {}".format(url))
                continue

            book_info = r.json()
            for p in book_info['children']:
                logging.info("page id " + p['content']['title'])
                page_id = p['content']['_id']
                url = "ullekhanam/v1/dbs/{}/pages/{}/annotations".format(Parms.dbname,
                    page_id)
                r = vvclient.get(url)
                if not r:
                    sys.exit(1)
                print_dict(r.json())
if __name__ == "__main__":
   main(sys.argv[1:])
