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

## Credits

1. [Bharat Chauhan Blog](https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/)
  - A great resource to get started and build upon
  