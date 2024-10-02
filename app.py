import socket
import uuid
import logging

# Setup the Logger
logger = logging.getLogger(__name__)
logging.basicConfig(filename='serverlog.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

class TCPServer:
    def __init__(self, port=8080) -> None:
        self.host = "127.0.0.1"
        self.port = port

    def start(self):

        # Setup the server  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(5)

        socketname = s.getsockname()
        logger.info(f"Server listening on: {socketname}")

        while True:
            # accept any new connection
            conn, addr = s.accept()

            logger.info(f"Connected by : {addr}")

            # read the data sent by the client (Only first 2048 bytes are read)
            data = conn.recv(2048)
            logger.info(f"Request received: {data.decode()}" )

            response = self.handle_request(data)

            logger.info(f"Response Sent: {response.decode()}")

            conn.sendall(response)
            conn.close()

    def handle_request(self, data):
        pass

class HTTPRequest:
    def __init__(self, data):
        self.method = None
        self.uri = None
        self.http_version = "1.1" # default to HTTP/1.1 if request doesn't provide a version

        self.headers = { }
        self.body = ""

        # call self.parse() method to parse the request data
        self.parse(data)
    
    def parse(self, data:str):
        lines = data.split("\r\n")

        request_line = lines[0]
        words = request_line.split(" ")
        self.method = words[0]

        if len(words) > 1:
            # we put this in an if-block because sometimes 
            # browsers don't send uri for homepage
            self.uri = words[1] # call decode to convert bytes to str

        if len(words) > 2:
            self.http_version = words[2]

        body = ''
        in_headers = True
        
        for line in lines[1:]:
            if line == '':
                in_headers = False
            elif in_headers:
                key, value = line.split(': ', 1)
                self.headers[key] = value
            else:
                body += line

        self.body = body
        return
    
    def extract_post_data(self, body:str):
        import json
        form = json.loads(body)
        logger.info(f"Form received: {form}")
        return form

class Router:
    def __init__(self) -> None:
        self.routes = {}

    def add_route(self, method, path, handler):
        self.routes[(method, path)] = handler

class HTTPResponse:
    status_codes = {
        200 : "OK", 
        404 : "Not Found",
        500: "Internal Server Error", 
        405: 'Method Not Allowed',
        400: 'Bad Request',
        401:'Unauthorized'
    }
    def __init__(self, status_code, extra_headers=None, body='') -> None:
        
        self.response_line = self.create_response_line(status_code)
        self.response_headers = self.create_response_headers(extra_headers, body)
        self.response_body = self.create_response_body(body=body)
    
    def create_response_line(self, status_code):
        """Returns response line"""
        reason = self.status_codes[status_code]
        line = "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        return line
    
    def create_response_headers(self, extra_headers=None, body=''):
        headers = {
            'Server': socket.gethostname()
        }
        headers_copy = headers # make a local copy of headers
        headers_copy['Content-Length'] = len(body)

        if extra_headers:
            headers_copy.update(extra_headers.items())

        headers = ""

        for h in headers_copy:
            headers += "%s: %s\r\n" % (h, headers_copy[h])

        return headers
    
    def create_response_body(self, body):
        return body

    def to_http(self) -> str:
        response_line = self.response_line.encode()
        response_headers = self.response_headers.encode()
        blank_line = b"\r\n"
        response_body = self.response_body.encode()
        return b"".join([response_line, response_headers, blank_line, response_body])

class HTTPServer(TCPServer):
    def __init__(self, port=8080) -> None:
        super().__init__(port)
        self.router = Router()
        self.SESSIONS = {}

    def handle_request(self, data):
        request = self.create_request(data.decode())
        response = self.create_response(request=request)
        return response.to_http()

    def create_request(self, data):
        request = HTTPRequest(data)
        return request
    
    def create_response(self, request:HTTPRequest) -> HTTPResponse:
        handler = self.router.routes[(request.method, request.uri)]
        if not handler:
            response = HTTPResponse(404)
        else:
            response = handler(request)
        return response
    
    def create_session(self, username):
        session_id = str(uuid.uuid4())
        self.SESSIONS[username] = session_id
        return session_id
        
    def delete_session(self, username):
        if username in self.SESSIONS:
            del self.SESSIONS[username]

    def handle_login(self, request:HTTPRequest) -> HTTPResponse:
        if request.method != "POST":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        if 'Content-Type' not in request.headers or request.headers['Content-Type'] != "application/json":
            return HTTPResponse(400)
        
        form = request.extract_post_data(request.body)

        if 'username' not in form:
            return HTTPResponse(400, body='Username not found')
        
        username = form['username']
        session_id = self.create_session(username)
        
        extra_headers = { 
            'Set-Cookie': f"session_id={session_id};username={username}"
        }

        logger.info(f"After login: {self.SESSIONS}")
        response = HTTPResponse(200, extra_headers=extra_headers, body="Login Successful")
        return response
    
    def handle_logout(self, request:HTTPRequest) -> HTTPResponse:
        if request.method != "POST":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        session_id = None
        if 'Cookie' not in request.headers:
            return HTTPResponse(400, body="You need to login before logging out!")
        
        cookies = request.headers['Cookie']
        for cookie in cookies.split(';'):
                if 'session_id' in cookie:
                    session_id = cookie.split('=')[1]
                if 'username' in cookie:
                    username = cookie.split('=')[1]
        
        if session_id:
            self.delete_session(username)
            logger.info(f"After logout: {self.SESSIONS}")
            return HTTPResponse(200, body="Logout successful!")

        else:
            return HTTPResponse(400, body="You need to login before logging out!")
        
    def handle_protected_resource(self, request:HTTPRequest) -> HTTPResponse:
        if request.method != "GET":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        if 'Cookie' not in request.headers:
            return HTTPResponse(401)
        session_id = None
        username = None
        cookies = request.headers['Cookie']
        for cookie in cookies.split(';'):
                if 'session_id' in cookie:
                    session_id = cookie.split('=')[1]
                if 'username' in cookie:
                    username = cookie.split('=')[1]
            

        if not session_id or username not in self.SESSIONS or self.SESSIONS[username] != session_id:
            return HTTPResponse(401)
        
        return HTTPResponse(200, body="You are accessing a protected resource")
        
    
if __name__ == '__main__':
    server = HTTPServer()
    server.router.add_route("POST", "/login", server.handle_login)
    server.router.add_route('POST', '/logout', server.handle_logout)
    server.router.add_route('GET', '/protected', server.handle_protected_resource)

    server.start()
