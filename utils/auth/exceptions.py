from fastapi import HTTPException

class InvalidUsernameOrEmail(HTTPException):
    def __init__(self):
        super().__init__(401, "Login or Email doesn't exist")


class InvalidPassword(HTTPException):
    def __init__(self):
        super().__init__(401, "Password is not correct")

class UserIsBlocked(HTTPException):
    def __init__(self):
        super().__init__(400, "User is blocked! Please try again later or contact support!")

