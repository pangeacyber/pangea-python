import base64
import json
import logging
from http.server import BaseHTTPRequestHandler

from app.app import App


class HttpHandler(BaseHTTPRequestHandler):
    """A simple web server"""

    def _set_response(self, code):
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def _get_user(self, encoded_str: str):
        split = encoded_str.strip().split(" ")

        username, password = base64.b64decode(split[1]).decode().split(":", 1)

        return username

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))

        # get the user from header
        user = self._get_user(self.headers["Authorization"])

        code, resp = self._route(self.path, user)

        self._set_response(code)

        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        logging.info(
            "POST request,\nPath: %s\nHeaders:\n%s\nClient: %s\n\nBody:\n%s\n",
            str(self.path),
            str(self.headers),
            str(self.client_address),
            post_data.decode("utf-8"),
        )

        # get the user from header
        user = self._get_user(self.headers["Authorization"])

        # get the payload
        body = json.loads(post_data.decode("utf-8"))

        # client = self.client_address[0] # gets the 'host' of client
        # Mock client IP, since localhost won't do here
        client = self.headers["ClientIPAddress"]

        code, resp = self._route(self.path, user, client, body)

        self._set_response(code)

        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def _route(self, path: str, user: str, client_ip: str = "", data: dict = None) -> (int, dict):

        app = App()
        path_tok = path.split("/")

        try:
            if path_tok[1] == "setup":
                app.setup()
                code = 200
                status = "App setup completed"
            elif path_tok[1] == "upload_resume":
                code, status = app.upload_resume(user, client_ip, data)
            elif path_tok[1] == "employee" and len(path_tok) == 3:
                code, status = app.fetch_employee_record(user, path_tok[2])
            elif path_tok[1] == "update_employee":
                code, status = app.update_employee(user, data)
            else:
                code = 400
                status = "Unsupported action "
        except Exception as e:
            logging.error(f"[_route] Exception: {str(e)}")
            code = 500
            status = "Server error"

        app.shutdown()

        logging.info(f"[_route] {code}, {status}")

        return (code, {"message": status})
