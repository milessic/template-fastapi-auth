# FastAPI template with working auth
## Testing
To test the login/register/token functionalities you can do it via web application, accessible from ``localhost:port`` leveraging browser authentication functionality (via auth cookie) or via REST calls, you can use scripts placed under ``./scripts/`` directory, e.g. ``./scripts/register_user_via_rest.py/`` that use ``requests`` library (which is not included in ``requirements.txt`` file.

## Environment setup
1. install python3
2. create venv
3. install ``requirements.txt``
4. initize sqlite database running python script ``./scripts/create_sqlite3_db.py``
4. run as uvicorn ``python3 -m uvicorn main:app --reload``


