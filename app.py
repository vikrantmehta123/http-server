import socket
import uuid
import logging
import threading
import base64
import hashlib
import hmac

# Setup the Logger
logger = logging.getLogger(__name__)
logging.basicConfig(filename='serverlog.log', encoding='utf-8', level=logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

# Setup the TCP Server: the base class for our HTTP Server
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

            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            logger.info(f"Being handled by the thread: {thread.native_id}, {thread.name}")
            thread.start()

            

    def handle_client(self, conn, addr):
        """Handle the client request in a new thread."""
        try:
            # read the data sent by the client (Only first 2048 bytes are read)
            data = conn.recv(2048)
            logger.info(f"Request received from {addr}: {data.decode()}")

            # Process the request
            response = self.handle_request(data)

            # Send response
            conn.sendall(response)
            logger.info(f"Response sent to {addr}: {response.decode()}")

        finally:
            # Close the connection once the request is handled
            conn.close()

    def handle_request(self, data):
        """Implementation handled by the child class"""
        pass

class HTTPRequest:
    """Class for the HTTP Requests"""
    def __init__(self, data):
        self.method = None
        self.uri = None
        self.http_version = "1.1" # default to HTTP/1.1 if request doesn't provide a version

        self.headers = { }
        self.body = ""

        # call self.parse() method to parse the request data
        self.parse(data)
    
    def parse(self, data:str):
        """Given an HTTP text request, parse the method, uri, headers and body of the request."""
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
            # Headers and body are separated by blank line. Check for it
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
        """We assume that the form is being submitted as type: application/json"""
        import json
        form = json.loads(body)
        logger.info(f"Form received: {form}")
        return form

class Router:
    def __init__(self) -> None:
        self.routes = {}

    def add_route(self, method:str, path:str, handler:classmethod):
        """Adds the route, path, and maps it with its handler function"""
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
        """Returns response line-> always a single line with specific format"""
        try:
            reason = self.status_codes[status_code]
            line = "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        except KeyError:
            status_code = 400
            reason = self.status_codes[status_code]
            line = "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        return line
    
    def create_response_headers(self, extra_headers=None, body=''):
        """Create the headers to be sent back to the client as a part of the response"""
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

    def to_http(self):
        """Concatenate the strings and encode them in bytes since we need to send bytes and not strings"""
        response_line = self.response_line.encode()
        response_headers = self.response_headers.encode()
        blank_line = b"\r\n"
        response_body = self.response_body.encode()
        return b"".join([response_line, response_headers, blank_line, response_body])
    
class SessionManager:
    """
    Class to manage user sessions.
    
    This class allows for the creation, deletion, and verification of user sessions, 
    typically used when a user logs in and logs out.
    """
    
    def __init__(self) -> None:
        """
        Initializes the session manager with an empty dictionary to store session data.
        """
        self.SESSIONS = {}  # Dictionary to store sessions for each user

    def create_session(self, username: str) -> str:
        """
        Creates a new session for the specified user.
        
        Args:
            username (str): The username of the user logging in.
        
        Returns:
            str: The generated session ID for the user.
        """
        # Generate a unique session ID using UUID
        session_id = str(uuid.uuid4())
        
        # Store the session ID for the user in the SESSIONS dictionary
        self.SESSIONS[username] = session_id
        
        # Return the session ID
        return session_id
        
    def delete_session(self, username: str) -> None:
        """
        Deletes the session for the specified user.
        
        This is typically used when the user logs out and will require logging in again.
        
        Args:
            username (str): The username of the user logging out.
        """
        # Check if the user has a session and remove it
        if username in self.SESSIONS:
            del self.SESSIONS[username]

    def exists(self, username: str, session_id: str = None) -> bool:
        """
        Checks whether the user is already logged in.
        
        Optionally, the session ID can be provided to check if a specific session exists for the user.
        
        Args:
            username (str): The username of the user to check.
            session_id (str, optional): The session ID to verify, if needed.
        
        Returns:
            bool: True if the user is logged in and the session ID (if provided) matches; False otherwise.
        """
        # If the user is not in the session list, return False
        if username not in self.SESSIONS:
            return False
        
        # If a session ID is provided, check if it matches the stored session ID
        if session_id and self.SESSIONS[username] != session_id:
            return False
        
        # If no session ID is provided or it matches, return True
        return True


class TokenManager:
    """
    A class to manage tokens using HMAC-SHA256 for signing and verifying tokens.
    """
    
    def __init__(self) -> None:
        """
        Initializes the TokenManager with the specified algorithm and an empty dictionary
        to store tokens. Uses HMAC-SHA256 as the hashing algorithm.
        """
        self.algorithm = 'HMAC-SHA256'
        self.TOKENS = {}  # Dictionary to store tokens for users

    def create_signature(self, header: str, payload: str, secret_key: str) -> str:
        """
        Creates an HMAC-SHA256 signature for a given header, payload, and secret key.
        
        Args:
            header (str): The token header in string form.
            payload (str): The token payload in string form.
            secret_key (str): The secret key used to sign the token.

        Returns:
            str: The generated signature.
        """
        # Ensure inputs are in bytes
        if not isinstance(header, bytes):
            header = header.encode('utf-8')
        if not isinstance(secret_key, bytes):
            secret_key = secret_key.encode('utf-8')
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')

        # Concatenate header and payload
        concat = f"{header}.{payload}"

        # Create the HMAC-SHA256 signature
        signature = hmac.new(secret_key, concat.encode('utf-8'), hashlib.sha256)

        # Return the signature in hexadecimal format
        return signature.hexdigest()

    def create_token(self, header: str, payload: str, secret_key: str) -> bytes:
        """
        Creates a token consisting of a header, payload, and HMAC-SHA256 signature.
        
        Args:
            header (str): The token header.
            payload (str): The token payload.
            secret_key (str): The secret key used to sign the token.
        
        Returns:
            bytes: The encoded token.
        """
        # Generate the signature
        signature = self.create_signature(header, payload, secret_key)

        # Combine header, payload, and signature into a single token string
        token = f"{header}.{payload}.{signature}"

        # Encode the token
        return self.encode_token(token)

    def encode_token(self, token: str) -> bytes:
        """
        Encodes the token using Base64 encoding.
        
        Args:
            token (str): The token to be encoded.
        
        Returns:
            bytes: The Base64-encoded token.
        """
        return base64.b64encode(token.encode('utf-8'))

    def decode_token(self, token: bytes) -> str:
        """
        Decodes the Base64-encoded token back into its original string format.
        
        Args:
            token (bytes): The Base64-encoded token.
        
        Returns:
            str: The decoded token as a string.
        """
        return base64.b64decode(token).decode('utf-8')

    def verify_identity(self, token: bytes) -> bool:
        """
        Verifies the identity by checking if the token is valid.
        
        Args:
            token (bytes): The Base64-encoded token to verify.
        
        Returns:
            bool: True if the token is valid, False otherwise.
        """
        # Decode the token
        token = self.decode_token(token)

        # Split the token into header, payload, and signature
        header, payload, signature = token.split(".")

        # Verify the signature
        return self.verify_signature(header, payload, signature)

    def verify_signature(self, header: str, payload: str, actual_signature: str) -> bool:
        """
        Verifies if the actual signature matches the expected signature for the given header and payload.
        
        Args:
            header (str): The token header.
            payload (str): The token payload.
            actual_signature (str): The actual signature provided with the token.
        
        Returns:
            bool: True if the signatures match, False otherwise.
        """
        # Recreate the expected signature based on the header and payload
        expected_signature = self.create_signature(header, payload, actual_signature)

        # Compare the actual signature with the expected signature
        return expected_signature == actual_signature

    def add_token(self, username: str, token: bytes) -> None:
        """
        Adds a token to the user's token storage.
        
        Args:
            username (str): The username to associate with the token.
            token (bytes): The token to store.
        """
        self.TOKENS[username] = token

    def delete_token(self, username: str) -> None:
        """
        Deletes a token associated with the given username.
        
        Args:
            username (str): The username whose token should be deleted.
        """
        if username in self.TOKENS:
            del self.TOKENS[username]


class HTTPServer(TCPServer):
    def __init__(self, port=8080, session_manager=None, token_manager=None, secret_key=None) -> None:
        super().__init__(port)
        self.router = Router()
        self.session_manager = SessionManager()
        self.SECRET_KEY = "my-secret-key"
        self.token_manager = TokenManager()

    def handle_request(self, data):
        request = self.create_request(data.decode())
        response = self.create_response(request=request)
        return response.to_http()

    def create_request(self, data):
        """Convert the incoming data into an HTTP Request instance"""
        request = HTTPRequest(data)
        return request
    
    def create_response(self, request:HTTPRequest) -> HTTPResponse:
        """Using the request, call the handler method"""
        try:
            handler = self.router.routes[(request.method, request.uri)]
        except KeyError:
            HTTPResponse(400)
        if not handler:
            response = HTTPResponse(404)
        else:
            response = handler(request)
        return response

    def handle_login(self, request:HTTPRequest) -> HTTPResponse:
        """Handler for the login endpoint"""
        # Error checking 
        if request.method != "POST":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        if 'Content-Type' not in request.headers or request.headers['Content-Type'] != "application/json":
            return HTTPResponse(400)
        
        form = request.extract_post_data(request.body)

        if 'username' not in form:
            return HTTPResponse(400, body='Username not found')
        
        # If request is valid, create a session for the user, and return the cookie as a part of the response.
        username = form['username']
        session_id = self.session_manager.create_session(username)
        
        extra_headers = { 
            'Set-Cookie': f"session_id={session_id};username={username}"
        }
        response = HTTPResponse(200, extra_headers=extra_headers, body="Login Successful")
        return response
    
    def handle_logout(self, request:HTTPRequest) -> HTTPResponse:
        """Handler for the logout endpoint"""

        # Error checking
        if request.method != "POST":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        session_id = None
        if 'Cookie' not in request.headers:
            return HTTPResponse(400, body="You need to login before logging out!")
        
        # Extract data from cookie
        cookies = request.headers['Cookie']
        for cookie in cookies.split(';'):
                if 'session_id' in cookie:
                    session_id = cookie.split('=')[1]
                if 'username' in cookie:
                    username = cookie.split('=')[1]
        
        # Delete the user's session- mark him / her as logged out
        if session_id:
            self.session_manager.delete_session(username)
            return HTTPResponse(200, body="Logout successful!")
        else:
            return HTTPResponse(400, body="You need to login before logging out!")
        
    def handle_protected_resource(self, request:HTTPRequest) -> HTTPResponse:
        """Handler for the protected endpoint"""

        # Error checking
        if request.method != "GET":
            return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

        if 'Cookie' not in request.headers:
            return HTTPResponse(401)
        
        # Extract session info from cookies
        session_id = None
        username = None
        cookies = request.headers['Cookie']
        for cookie in cookies.split(';'):
                if 'session_id' in cookie:
                    session_id = cookie.split('=')[1]
                if 'username' in cookie:
                    username = cookie.split('=')[1]
            
        # If the user is logged in, allow him to access the resource. Else return unauthorized
        if not session_id or self.session_manager.exists(username, session_id):
            return HTTPResponse(401)
        
        return HTTPResponse(200, body="You are accessing a protected resource")
        
    
if __name__ == '__main__':
    server = HTTPServer()
    server.router.add_route("POST", "/login", server.handle_login)
    server.router.add_route('POST', '/logout', server.handle_logout)
    server.router.add_route('GET', '/protected', server.handle_protected_resource)

    server.start()
