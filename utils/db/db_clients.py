from utils.db.sqlte3_connector import SqLite3Connector
from utils.db.queries import *
from fastapi import status, HTTPException


class DbClient():
    def __init__(self, database_name:str, database_type:str="sqlite3"):
        self.database_type = database_type
        self.client = SqLite3Connector(f"{database_name}.db")

    def _execute(self, query, *args) -> list|dict|None:
        output = self.client.execute(query[self.database_type], *args)
        try:
            if str(output[0][0]).startswith("ERROR:"):
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, output)
            return output
        except IndexError:
            return None

    def create_tables(self):
        self._execute(query_create_users_table)
        self._execute(query_create_friendships_table)
        self._execute(query_create_friendship_users_table)
        self._execute(query_create_avatars_table)


    def create_user(self, user_details:dict):
        self._execute(query_create_user_record, *[user_details["username"], user_details["password"], user_details["email"]])
        user_id = self.get_user_id_from_username(user_details["username"])
        self._execute(query_create_avatar, user_id, None, None)

    def delete_user(self, username:str, user_id:str):
        self._execute(query_delete_user, username, user_id) # TODO do it different way in the future

    def get_user_data(self, login):
        output = self._execute(query_get_user_data_by_username_or_id, login, login)
        try:
            return output[0][0]
        except:
            return False

    def get_friendship_status(self, friendship_id) -> int | None:
        output = self._execute(query_check_friendship, friendship_id)
        try:
            return output[0][0]
        except:
            return None
    

    def check_if_username_exists(self, username):
        result = self._query_output_to_bool(self._execute(query_check_if_username_exists, username))
        return not(result)

    def check_if_email_exists(self, email):
        return not(self._query_output_to_bool(self._execute(query_check_if_username_exists, email)))
    

    def update_avatar(self, user_id, filename, new_avatar:bytes|None):
        p = self._execute(query_update_avatar, filename, new_avatar, user_id)


    def get_avatar(self, user_id) -> dict:
        output = self._execute(query_get_avatar_by_user_id, user_id)
        return {"filename": output[0][0][0], "content": output[0][0][1]}

    def get_user_id_from_username(self, username):
        return self._execute(query_get_user_id_by_username, username)[0][0][0]

    def _query_output_to_bool(self, output) -> bool:
        if output is None:
            return True
        try:
            return output[0][0]
        except IndexError:
            return True
