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

class TCPServer:
    """
    A base class for creating a TCP server that listens for client connections and handles requests.
    This server uses multithreading to handle multiple clients concurrently.

    Attributes:
        host (str): The IP address where the server will listen (default is localhost).
        port (int): The port on which the server will listen (default is 8080).
    """

    def __init__(self, port=8080) -> None:
        """
        Initializes the TCPServer instance with a specific port.
        
        Args:
            port (int): The port number for the server to listen on (default is 8080).
        """
        self.host = "127.0.0.1"  # Server will bind to localhost by default
        self.port = port  # Port the server will listen on

    def start(self):
        """
        Starts the TCP server, binds to the specified host and port, and listens for incoming connections.
        Each client is handled in a new thread.
        """
        # Create a new socket using IPv4 (AF_INET) and TCP (SOCK_STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind the socket to the provided host and port
        s.bind((self.host, self.port))
        
        # Start listening for incoming connections with a backlog of 5
        s.listen(5)

        # Get the socket's information and log it
        socketname = s.getsockname()
        logger.info(f"Server listening on: {socketname}")

        while True:
            # Accept a new connection (blocking call)
            conn, addr = s.accept()
            logger.info(f"Connected by : {addr}")

            # Handle each connection in a new thread
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            logger.info(f"Being handled by thread: {thread.native_id}, {thread.name}")
            thread.start()

    def handle_client(self, conn, addr):
        """
        Handles the client request in a separate thread.
        Reads data from the client, processes the request, and sends back a response.
        
        Args:
            conn (socket): The socket object representing the client connection.
            addr (tuple): The address of the connected client (IP, port).
        """
        try:
            # Read data from the client (up to 2048 bytes)
            data = conn.recv(2048)
            logger.info(f"Request received from {addr}: {data.decode()}")

            # Process the client request and generate a response
            response = self.handle_request(data)

            # Send the response back to the client
            conn.sendall(response)
            logger.info(f"Response sent to {addr}: {response.decode()}")

        finally:
            # Close the connection after processing the request
            conn.close()

    def handle_request(self, data):
        """
        Processes the incoming request data. This method is intended to be 
        implemented by subclasses to handle specific protocols (e.g., HTTP).
        
        Args:
            data (bytes): The raw data received from the client.
        
        Returns:
            bytes: The response data to be sent back to the client.
        
        Note:
            This method must be implemented in the subclass to define the 
            behavior of the server (e.g., handling HTTP requests).
        """
        raise NotImplementedError("Subclasses must implement this method to handle client requests.")

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
    """
    A simple Router class that maps HTTP methods and paths to handler functions.
    
    Attributes:
        routes (dict): A dictionary that stores routes, where keys are tuples of (method, path),
                       and values are handler functions for processing those routes.
    """

    def __init__(self) -> None:
        """
        Initializes the Router instance with an empty dictionary for routes.
        """
        self.routes = {}  # Dictionary to store routes

    def add_route(self, method: str, path: str, handler: classmethod):
        """
        Adds a route to the router by mapping an HTTP method and path to a handler function.
        
        Args:
            method (str): The HTTP method for the route (e.g., "GET", "POST").
            path (str): The path for the route (e.g., "/home", "/about").
            handler (classmethod): The handler function that will process requests for this route.
        """
        # Add the route to the dictionary
        self.routes[(method, path)] = handler

class HTTPResponse:
    """
    A class to generate HTTP responses with status codes, headers, and body.
    
    Attributes:
        status_codes (dict): A dictionary mapping HTTP status codes to their reason phrases.
    """

    status_codes = {
        200: "OK", 
        404: "Not Found",
        500: "Internal Server Error", 
        405: 'Method Not Allowed',
        400: 'Bad Request',
        401: 'Unauthorized'
    }

    def __init__(self, status_code, extra_headers=None, body='') -> None:
        """
        Initializes an HTTPResponse object with a status code, optional extra headers, and a response body.
        
        Args:
            status_code (int): The HTTP status code for the response.
            extra_headers (dict, optional): Additional headers to include in the response.
            body (str, optional): The response body content (default is an empty string).
        """
        self.response_line = self.create_response_line(status_code)  # Create the response line (HTTP/1.1 <status_code> <reason>)
        self.response_headers = self.create_response_headers(extra_headers, body)  # Create the headers for the response
        self.response_body = self.create_response_body(body=body)  # Store the response body

    def create_response_line(self, status_code):
        """
        Creates the HTTP response line in the format: "HTTP/1.1 <status_code> <reason_phrase>\r\n".
        
        Args:
            status_code (int): The HTTP status code.
        
        Returns:
            str: The response line formatted with the status code and its corresponding reason phrase.
        """
        try:
            # Fetch the reason phrase based on the status code
            reason = self.status_codes[status_code]
            line = "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        except KeyError:
            # If the status code is invalid, default to 400 (Bad Request)
            status_code = 400
            reason = self.status_codes[status_code]
            line = "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        return line

    def create_response_headers(self, extra_headers=None, body=''):
        """
        Creates the HTTP response headers including server information, content length, and any extra headers.
        
        Args:
            extra_headers (dict, optional): Additional headers to include in the response.
            body (str): The body content for calculating content length.
        
        Returns:
            str: The formatted HTTP response headers.
        """
        # Create default headers, including the server's hostname
        headers = {
            'Server': socket.gethostname()  # Get the server's hostname for the 'Server' header
        }
        
        # Copy headers and add the 'Content-Length' header based on the body size
        headers_copy = headers
        headers_copy['Content-Length'] = len(body)

        # If there are extra headers, update the copy with additional headers
        if extra_headers:
            headers_copy.update(extra_headers.items())

        # Build the headers as a string in HTTP format
        headers = ""
        for h in headers_copy:
            headers += "%s: %s\r\n" % (h, headers_copy[h])

        return headers

    def create_response_body(self, body):
        """
        Creates the response body content.
        
        Args:
            body (str): The body content to be included in the HTTP response.
        
        Returns:
            str: The response body.
        """
        return body

    def to_http(self):
        """
        Converts the entire HTTP response (line, headers, body) into a single byte-encoded string.
        
        Returns:
            bytes: The HTTP response encoded in bytes, ready to be sent over a socket.
        """
        # Encode the response line and headers
        response_line = self.response_line.encode()
        response_headers = self.response_headers.encode()

        # A blank line to separate headers from the body
        blank_line = b"\r\n"

        # Encode the response body
        response_body = self.response_body.encode()

        # Concatenate everything and return it as a byte string
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
        if not session_id:
            return False

        if self.SESSIONS[username] != session_id:
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
    def __init__(self, port=8080) -> None:
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
        if not session_id or not self.session_manager.exists(username, session_id):
            return HTTPResponse(401)
        
        return HTTPResponse(200, body="You are accessing a protected resource")


if __name__ == '__main__':
    server = HTTPServer()
    server.router.add_route("POST", "/login", server.handle_login)
    server.router.add_route('POST', '/logout', server.handle_logout)
    server.router.add_route('GET', '/protected', server.handle_protected_resource)

    server.start()
