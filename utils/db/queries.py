# CREATE TABLES
query_create_users_table = {
        "sqlite3": (
            """
            CREATE TABLE IF NOT EXISTS 
            users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE, 
            username TEXT NOT NULL UNIQUE, 
            email TEXT NOT NULL UNIQUE, 
            password TEXT NOT NULL, 
            password_updated INTEGER, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            two_factor INTEGER 
            );
            """
            )
        }

query_create_avatars_table = {
        "sqlite3":(
            """
            CREATE TABLE IF NOT EXISTS 
            avatars (
            user_id INTEGER NOT NULL UNIQUE,
            filename STRING, 
            avatar BLOB
            )
            """
            )
        }

query_create_friendships_table = {
        "sqlite3":(
            """
            CREATE TABLE IF NOT EXISTS 
            friendships (
            friendship_id TEXT PRIMARY KEY UNIQUE NOT NULL, 
            status INTEGER NOT NULL
            );
            """
            )
        }
query_create_friendship_users_table = {
        "sqlite3":(
            """
            CREATE TABLE IF NOT EXISTS 
            friendship_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
            friendship_id TEXT NOT NULL,
            user_id INTEGER NOT NULL
            );
            """
            )
        }

# FRIENDSHIP QUERIES
query_check_friendship = {
        "sqlite3":(
            """
            SELECT status 
            FROM friendships 
            WHERE 
            friendship_id = (?)
            """
            )
        }
query_create_friendship = {
        "sqlite3":(
            """INSERT INTO friendships
            (friendship_id, status) 
            VALUES ((?),(?))
            """
            )
        }

query_update_friendship_status = {
        "sqlite3":(
            """
            UPDATE friendships 
            SET status = ((?)) 
            WHERE friendship_id = ((?))
            """
            )
        }

query_create_friendship_users_record = {
        "sqlite3":"""
        INSERT INTO friendship_users 
        (friendship_id, user_id)
        VALUES ((?), (?))
        """
        }

query_get_active_friendships_for_user = {
        "sqlite3":"""
        SELECT 
            friendship_id
        FROM
            friendship_users
        INNER JOIN friendships ON friendship_users.friendship_id = friendships.friendship_id
        WHERE
            user_id = (?)
        AND
            friendship_status = 1
        """
        }

query_delete_friendship_record = {
        "sqlite3":(
            """
            DELETE FROM friendships
            WHERE friendship_id = (?)
            """
            )
        }

query_delete_friendship_users_record = {
        "sqlite3":(
            """
            DELETE FROM friendship_users
            WHERE friendship_id = (?)
            """
            )
        }

# AVATARS QUERIES
query_create_avatar = {
        "sqlite3":(
            """
            INSERT INTO avatars
            (
            user_id, filename, avatar
            )
            VALUES
            ( (?), (?), (?) )
            

            """
            )
        }

query_update_avatar = {
        "sqlite3":(
            """
            UPDATE avatars 
            set filename =(?), avatar = (?) 
            WHERE 
            user_id = (?)
            """
            )
        }

query_get_avatar_by_user_id = {
        "sqlite3":(
            """
            SELECT filename, avatar
            FROM avatars
            WHERE user_id = (?)
            """
            )
        }


query_delete_avatar = {
        "sqlite3":(
            """
            UPDATE avatars
            set avatar = NULL
            WHERE
            user_id = (?)
            """
            )
        }

# USER QUERIES
query_create_user_record = {
        "sqlite3":(
            """
            INSERT INTO users
            (
            username, password, email
            )
            VALUES ((?), (?), (?))
            """
            )
        }

query_delete_user = {
        "sqlite3":(
            """
            DELETE FROM users
            WHERE username = (?) AND user_id = (?)
            LIMIT 1
            """
            )
        }

query_get_user_data_by_username_or_id = {
        "sqlite3":(
            """
            SELECT username, email, password 
            FROM users 
            WHERE UPPER(username)=UPPER((?)) OR UPPER(email)=UPPER((?))
            """
            )
        }

query_check_if_username_exists = {
        "sqlite3":(
            """
            SELECT username 
            FROM users 
            WHERE username=(?)
            COLLATE NOCASE
            """
            )
        }

query_check_if_email_exists = {
        "sqlite3":(
            """
            SELECT email 
            FROM users 
            WHERE email=(?)
            COLLATE NOCASE
            )
            """
            )
        }

query_get_user_id_by_username = {
        "sqlite3":(
            """
            SELECT user_id
            FROM users
            WHERE UPPER(username)=UPPER((?))
            """
            )
        }
