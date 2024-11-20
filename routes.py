from .app import *

@server.add_route(['POST'], '/login')
def handle_login(request:HTTPRequest) -> HTTPResponse:
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
    session_id = server.session_manager.create_session(username)
    
    extra_headers = { 
        'Set-Cookie': f"session_id={session_id};username={username}"
    }
    response = HTTPResponse(200, extra_headers=extra_headers, body="Login Successful")
    return response

@server.add_route(['POST'], '/logout')
def handle_logout(request:HTTPRequest) -> HTTPResponse:
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
        server.session_manager.delete_session(username)
        return HTTPResponse(200, body="Logout successful!")
    else:
        return HTTPResponse(400, body="You need to login before logging out!")
    
@server.add_route(['GET'], '/protected')
def handle_protected_resource(request:HTTPRequest) -> HTTPResponse:
    """Handler for the protected endpoint"""

    # Error checking
    if request.method != "GET":
        return HTTPResponse(405, body="The method you tried is not allowed on this endpoint")

    if 'Cookie' not in request.headers:
        print(request.headers)
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
    if not server.session_manager.exists(username, session_id):
        return HTTPResponse(401)
    
    return HTTPResponse(200, body="You are accessing a protected resource")
