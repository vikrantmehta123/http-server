# Simple HTTP Server

This project is a basic implementation of an HTTP server from scratch. It supports a minimal set of features, focusing on understanding how servers operate at a fundamental level. The server can handle a few HTTP routes and implements a basic request-response cycle.

## Features

- **Routes**: The server supports three main endpoints:
  - `POST /login`: Authenticates a user and creates a session.
  - `POST /logout`: Logs out the user and deletes the session.
  - `GET /protected`: Accesses a protected resource, requiring user authentication.

- **Session Management**: Sessions are managed using unique session IDs, allowing for user authentication across requests.

- **Basic HTTP Response Codes**: The server returns standard HTTP response codes:
  - `200 OK`
  - `404 Not Found`
  - `500 Internal Server Error`
  - `401 Unauthorized`
  - `405 Method Not Allowed`
  - `400 Bad Request`

- **Supports Multithreading**: The server can handle upto five concurrent requests.

If you wish, you could extend the server by adding some custom routes. You only need to define a couple of decorator functions to enable this:

```
def add_route(self, methods, path):
    """Decorator for adding routes."""
    def decorator(func):
        for method in methods:
            HTTPServer.registered_routes.append((method, path, func))
        return func
    return decorator

def register_routes(self):
    """Register all collected routes before starting the server."""
    for method, path, handler in HTTPServer.registered_routes:
        self.router.add_route(method, path, handler)
```

Paste the above code in the HTTP server class. Then you can define your own functions wrapped in the decorator much like in Flask. ( You also need to add a `registered_routes` attribtute which will be the list of all registered routes that your server can serve. ) Below is an example:

```
@server.add_route(['POST'], '/login')
def handle_login(request:HTTPRequest) -> HTTPResponse:
  pass
```

## Credits

1. [Bharat Chauhan Blog](https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/)
  - A great resource to get started and build upon
  