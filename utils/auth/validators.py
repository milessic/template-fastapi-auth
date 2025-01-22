import json
import re

def validate_username(username, db_client) -> str:
    r"""returns string with errors
    a - already exists
    s - username contains not-valid character # TODO
    """
    err = ""
    if db_client.check_if_username_exists(username):
        return "a"
    if "@" in username:
        err += "s"
    return err



def validate_password(password) -> str:
    r"""returns string with errors
    q - too short 
    w - too long  
    e - no number   # TODO
    r - no special sign  # TODO
    t - invalid characters  # TODO
    """
    err_str = ""
    if len(password) < 6:
        err_str += "q"
    if len(password) > 32:
        err_str += "w"
    return err_str

def validate_email(email, db_client) -> str:
    r"""returns string with errors
    z - already exists
    x - email has improper format
    c - something is wrong # TODO
    """
    err = ""
    if db_client.check_if_email_exists(email):
        return "z"
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        err += "x"
    return err

def generate_username_response(errors:str):
    if not(errors):
        raise ValueError(f"Errors were '{errors}' which is unexpected!")
    errors_list = []
    for letter in errors:
        match letter:
            case "a":
                errors_list.append("Username is already taken! Use other one!")
            case "s":
                errors_list.append("Username contains illegal characters")
            case _:
                errors_list.append(f"Some other problem{errors}")
        return errors_list

def generate_password_response(errors:str):
    if not(errors):
        raise ValueError(f"Errors were '{errors}' which is unexpected!")
    errors_list = []
    for letter in str(errors):
        match letter:
            case "q":
                errors_list.append("Password is too short! It has to be at least 7 characters long!")
            case "w":
                errors_list.append("Password is too long! It has to be maximum least 32 characters long!")
            case _:
                errors_list.append(f"Some other problem{errors}")
        return json.dumps(errors_list)

def generate_email_response(errors:str):
    if not(errors):
        raise ValueError(f"Errors were {errors}' which is unexpected!")
    errors_list = []
    for letter in errors:
        match letter:
            case "z":
                errors_list.append("Email is already taken! Use other one!")
            case "x":
                errors_list.append("This email address is invalid!")
            case _:
                errors_list.append(f"Some other problem{errors}")
        return errors_list


