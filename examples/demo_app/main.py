import logging
from sys import argv

from http.server import HTTPServer
from utils.http import HttpHandler

def run(server_class=HTTPServer, handler_class=HttpHandler, port=8080):
    logging.basicConfig(filename='myapp.log', level=logging.DEBUG)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')

    print(f'Running Demo App Server at http://localhost:{port}...\nLogs at "myapp.log"\n\nPress Ctrl-C to exit.')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == "__main__":
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
