import unittest
import requests

class TestServerRequests(unittest.TestCase):

    def setUp(self):
        # This method is called before each test case
        self.base_url = "http://127.0.0.1:8080"
        self.username = "testuser"

    def test_make_login_request(self):
        """Test login request"""
        data = {'username': self.username}
        headers = {'Content-Type': "application/json"}
        
        # Make the POST request
        res = requests.post(f"{self.base_url}/login", headers=headers, json=data)

        # Assertions to verify login was successful
        self.assertEqual(res.status_code, 200, "Login failed!")  # Expecting HTTP 200
        self.assertIn('Set-Cookie', res.headers, "No cookie set!")
        self.assertTrue(res.content, "Response content is empty!")

    def test_make_logout_request(self):
        """Test logout request"""
        # First, log in to get a valid cookie
        data = {'username': self.username}
        headers = {'Content-Type': "application/json"}
        login_res = requests.post(f"{self.base_url}/login", headers=headers, json=data)

        # Extract the cookie from the login response
        cookie = login_res.headers.get('Set-Cookie')
        self.assertIsNotNone(cookie, "Cookie is None after login!")
        
        # Make the logout request
        headers = {'Cookie': cookie}
        logout_res = requests.post(f"{self.base_url}/logout", headers=headers)

        # Assertions to verify logout was successful
        self.assertEqual(logout_res.status_code, 200, "Logout failed!")
        self.assertTrue(logout_res.content, "Response content is empty after logout!")

    def test_make_protected_request(self):
        """Test accessing a protected resource"""
        # First, log in to get a valid cookie
        data = {'username': self.username}
        headers = {'Content-Type': "application/json"}
        login_res = requests.post(f"{self.base_url}/login", headers=headers, json=data)

        # Extract the cookie from the login response
        cookie = login_res.headers.get('Set-Cookie')
        self.assertIsNotNone(cookie, "Cookie is None after login!")

        # Make the protected resource request
        headers = {'Cookie': cookie}
        protected_res = requests.get(f"{self.base_url}/protected", headers=headers)

        # Assertions to verify access to the protected resource
        self.assertEqual(protected_res.status_code, 200, "Access to protected resource failed!")
        self.assertTrue(protected_res.content, "Response content is empty for protected resource!")

import threading
import time

class TestMultithreading(unittest.TestCase):

    def make_protected_request(self, index):
        """Simulates a request to a protected resource"""
        headers = {}
        res = requests.get("http://127.0.0.1:8080/protected", headers=headers)

    def test_multithreading(self):
        """Test if server handles multiple requests concurrently"""
        threads = []
        start_time = time.time()

        # Simulate 5 concurrent requests
        for i in range(5):
            t = threading.Thread(target=self.make_protected_request, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        end_time = time.time()
        total_time = end_time - start_time

        # Expecting total time to be less than 2 seconds (because of multithreading)
        print(f"Total time taken: {total_time} seconds")
        self.assertTrue(total_time < 4, "Multithreading is not working properly!")

if __name__ == '__main__':
    unittest.main()
    