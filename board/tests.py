import random
from django.test import TestCase, Client
from board.models import CustomUser, FriendshipRequest, Friendship, FriendGroup, Conversation, Message, UserConversationStatus, Invitation, GroupAnnouncement
from datetime import datetime, timedelta
from django.utils import timezone
import hashlib
import hmac
import time
import json
import base64

from utils.utils_jwt import EXPIRE_IN_SECONDS, SALT, b64url_encode

phone = "12345678900"
email = "example@example.com"
password = "123456"
username = "Alice"
username2 = "Bob"
data_register = {
        "username": username, 
        "password": password,
        "email": email,
        "phone": phone
        }
data_register2 = {
        "username": username2, 
        "password": password,
        "email": email,
        "phone": phone
        }
data_login= {
        "username": username, 
        "password": password,
        }
# Create your tests here.
class BoardTests(TestCase):
    # Initializer
    
        
    # ! Utility functions
    def generate_jwt_token(self, username: str, payload: dict, salt: str):
        # * header
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        # dump to str. remove `\n` and space after `:`
        header_str = json.dumps(header, separators=(",", ":"))
        # use base64url to encode, instead of base64
        header_b64 = b64url_encode(header_str)
        
        # * payload
        payload_str = json.dumps(payload, separators=(",", ":"))
        payload_b64 = b64url_encode(payload_str)
        
        # * signature
        signature_str = header_b64 + "." + payload_b64
        signature = hmac.new(salt, signature_str.encode("utf-8"), digestmod=hashlib.sha256).digest()
        signature_b64 = b64url_encode(signature)
        
        return header_b64 + "." + payload_b64 + "." + signature_b64

    
    def generate_header(self, username: str, payload: dict = {}, salt: str = SALT):
        if len(payload) == 0:
            payload = {
                "iat": int(time.time()),
                "exp": int(time.time()) + EXPIRE_IN_SECONDS,
                "data": {
                    "username": username
                }
            }
        return {
            "HTTP_AUTHORIZATION": self.generate_jwt_token(username, payload, salt)
        }




    # ! Test section
    # * Tests for login view
    def test_register_succeed(self):
        res = self.client.post('/user/register', data=data_register, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(CustomUser.objects.filter(username=username).exists())

    def test_register_existing_user(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/register', data=data_register, content_type='application/json')
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 10)

    def test_register_invalid(self):
        data1 = {
                "username": "", 
                "password": password,
                "email":email,
                "phone": phone
                }
        data2 = {
                "username": "4932857382943284239334234", 
                "password": password,
                "email": email, 
                "phone": phone
                }
        data3 = {
                "username": username,
                "password": "",
                "email": email,
                "phone": phone
                }
        data4 = {
                "username": username,
                "password": "123456nejksfnjfjksadnjksand",
                "email": email,
                "phone": phone
                }
        data5 = {
                "username": username,
                "password": password,
                "email": "",
                "phone": phone
                }
        data6 = {
                "username": username, 
                "password": password,
                "email": "143242",
                "phone": phone
                }
        data7 = {
                "username": username, 
                "password": password,
                "email": email,
                "phone": "" 
                }
        data8 = {
                "username": username, 
                "password": password,
                "email": email,
                "phone": "1234567890a"
                },
        for data in [data1, data2, data3, data4, data5, data6, data7, data8]:
            res = self.client.post('/user/register', data=data, content_type='application/json')
            self.assertEqual(res.status_code, 400)
            self.assertEqual(res.json()['code'], -2)
        
    def test_login_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/login', data=data_login, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(res.json()['token'].count('.') == 2)

    def test_login_user_not_exist(self):
        res = self.client.post('/user/login', data=data_login, content_type='application/json')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 2)

    def test_login_incorrect_password(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/login', data={"username": username, "password": "1234567"}, content_type='application/json')
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], 15)

    def test_logoff_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/logoff', data={"password": password}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)

    def test_logoff_user_not_logged_in(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/logoff', data={"password": password}, content_type='application/json')
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.json()['code'], 1)

    def test_logoff_incorrect_password(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/logoff', data={"password": "1234567"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], 15)

    def test_update_normal_info_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.put('/user/update_normal_info', data={"avatar_base64": "https://example.com"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(CustomUser.objects.filter(username=username, avatar_base64="https://example.com").exists())

    def test_update_auth_info_username_exist(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.put('/user/update_auth_info', data={"username": username,"new_password": "1234567", "email": email, "phone": phone, "old_password": password}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 10)

    def test_update_auth_info_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.put('/user/update_auth_info', data={"username": username2,"new_password": "", "email": "", "phone": "", "old_password": password}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(CustomUser.objects.filter(username=username2).exists())

    def test_update_auth_info_incorrect_password(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.put('/user/update_auth_info', data={"username": username2,"new_password": "",  "email": "", "phone": "","old_password": "12456"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 403)
        self.assertEqual(res.json()['code'], 15)

    def test_search_friends_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        res = self.client.get('/user/search_friends?keyword=o', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()['data']
        self.assertEqual(len(response_data), 1)
        usernames= [data['username'] for data in response_data]
        self.assertTrue(username2  in usernames)
        self.assertFalse(username  in usernames)

    def test_get_user_profile_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')

        res = self.client.get('/user/profile/Alice', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()
        self.assertEqual(response_data['username'], username)
        self.assertEqual(response_data['is_friend'], True)

        res = self.client.get('/user/profile/Bob', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()
        self.assertEqual(response_data['username'], username2)
        self.assertEqual(response_data['is_friend'], False)

        self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        res = self.client.get('/user/profile/Bob', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()
        self.assertEqual(response_data['username'], username2)
        self.assertEqual(response_data['is_friend'], True)

    def test_get_user_profile_user_not_exist(self):
        res = self.client.get('/user/profile/Bob', **self.generate_header(username))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 20)

    def test_send_friend_request_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        res = self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(FriendshipRequest.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).exists())

    def test_send_friend_request_user_not_exist(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/send_friend_request', data={"friend_id": 3}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 20)
        self.assertFalse(FriendshipRequest.objects.filter(user_id=CustomUser.objects.get(username=username), friend_id=3).exists())

    def test_send_friend_request_self_request(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username).id}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()['code'], 23)

    def test_send_friend_request_already_friends(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username).id, friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        res = self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 24)
        
    def test_send_friend_request_already_request_exist(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        res = self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 25)

    def test_send_friend_request_already_request_exist_reverse(self):    
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        res = self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username).id}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(FriendshipRequest.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2),status="accept").exists())
        self.assertTrue(FriendshipRequest.objects.filter(user=CustomUser.objects.get(username=username2), friend=CustomUser.objects.get(username=username),status="accept").exists())
        self.assertTrue(Friendship.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).exists())
        self.assertTrue(Friendship.objects.filter(user=CustomUser.objects.get(username=username2), friend=CustomUser.objects.get(username=username)).exists())
        
    def test_send_friend_request_after_delete_friend(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        self.client.post('/user/delete_friend', data={"friend_id": CustomUser.objects.get(username=username).id}, content_type='application/json', **self.generate_header(username2))
        res=self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(FriendshipRequest.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).exists())

    def test_get_friend_requests_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        res = self.client.get('/user/friend_requests', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()['requests']
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['sender_id'], CustomUser.objects.get(username=username).id)
        res = self.client.get('/user/friend_requests', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()['sent_requests']
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['receiver_id'], CustomUser.objects.get(username=username2).id)

    def test_accept_friend_request_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        res = self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(Friendship.objects.filter(user_id=CustomUser.objects.get(username=username), friend_id=CustomUser.objects.get(username=username2)).exists())
        self.assertTrue(Friendship.objects.filter(user_id=CustomUser.objects.get(username=username2), friend_id=CustomUser.objects.get(username=username)).exists())
        status = FriendshipRequest.objects.get(user_id=CustomUser.objects.get(username=username), friend_id=CustomUser.objects.get(username=username2)).status
        self.assertEqual(status, "accept")
        
    def test_reject_friend_request_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        res = self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username).id, friend=CustomUser.objects.get(username=username2)).id, "response": "reject"}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertFalse(Friendship.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).exists())
        status = FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).status
        self.assertEqual(status, "reject")

    def test_respond_friend_request_not_exist(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/logoff', data={"password": password}, content_type='application/json', **self.generate_header(username))
        res = self.client.post('/user/respond_friend_request', data={"request_id": 1, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 21)

    def test_delete_friend_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        friend_id= CustomUser.objects.get(username=username2).id
        self.client.post('/user/send_friend_request', data={"friend_id": friend_id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        res = self.client.post('/user/delete_friend', data={"friend_id": CustomUser.objects.get(username=username).id}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertFalse(Friendship.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).exists())
        self.assertFalse(Friendship.objects.filter(user=CustomUser.objects.get(username=username2), friend=CustomUser.objects.get(username=username)).exists())

    def test_delete_friend_not_friend(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        res = self.client.post('/user/delete_friend', data={"friend_id": CustomUser.objects.get(username=username).id}, content_type='application/json', **self.generate_header(username2))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 26)

    def test_delete_friend_not_exist(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        res = self.client.post('/user/delete_friend', data={"friend_id": 2}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['code'], 22)
        
    def test_get_friends_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        res = self.client.get('/user/get_friends', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()['groups']
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['group_name'], '')
        self.assertEqual(response_data[0]['group_friends'][0]['friend_name'], username2)
        res = self.client.get('/user/get_friends', **self.generate_header(username2))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        response_data = res.json()['groups']
        self.assertEqual(len(response_data), 1)
        self.assertEqual(response_data[0]['group_name'], '') 
        self.assertEqual(response_data[0]['group_friends'][0]['friend_name'], username)


    def test_add_friend_to_group_succeed(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        self.client.post('/user/send_friend_request', data={"friend_id": CustomUser.objects.get(username=username2).id}, content_type='application/json', **self.generate_header(username))
        self.client.post('/user/respond_friend_request', data={"request_id": FriendshipRequest.objects.get(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2)).id, "response": "accept"}, content_type='application/json', **self.generate_header(username2))
        res = self.client.post('/user/add_friend_to_friend_group', data={"friend_id": CustomUser.objects.get(username=username2).id, "friend_group_name": "group1"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        self.assertTrue(Friendship.objects.filter(user=CustomUser.objects.get(username=username), friend=CustomUser.objects.get(username=username2), friend_group=FriendGroup.objects.get(user=CustomUser.objects.get(username=username), name="group1")).exists())
        res = self.client.post('/user/add_friend_to_friend_group', data={"friend_id": CustomUser.objects.get(username=username2).id, "friend_group_name": ""}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['code'], 0)
        
    def test_add_friend_to_group_not_friend(self):
        self.client.post('/user/register', data=data_register, content_type='application/json')
        self.client.post('/user/register', data=data_register2, content_type='application/json')
        res = self.client.post('/user/add_friend_to_friend_group', data={"friend_id": CustomUser.objects.get(username=username2).id, "friend_group_name": "group1"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 26)
        res = self.client.post('/user/add_friend_to_friend_group', data={"friend_id": 0, "friend_group_name": "group1"}, content_type='application/json', **self.generate_header(username))
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()['code'], 26)

    def test_get_private_conversations(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.conversation = Conversation.objects.create(name="Chat1", type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        
        # Test case 1: User not logged in
        response = self.client.get('/user/get_private_conversations')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Successful retrieval of private conversations
        self.client.login(username="user1", password="password1")  # Ensuring the user is logged in
        response = self.client.get('/user/get_private_conversations', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['conversations']), 1)
        self.assertEqual(data['conversations'][0]['name'], "user2")
        self.assertFalse(data['conversations'][0]['is_group'])

        # Test case 3: User does not exist
        self.client.logout()
        response = self.client.get('/user/get_private_conversations', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 404)
        self.assertIn("User does not exist", response.content.decode())

    # def test_create_private_conversation(self):
    #     self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
    #     self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
    #     self.user3 = CustomUser.objects.create_user(username="user3", password="password3")  # No friendship with user1
    #     Friendship.objects.create(user=self.user1, friend=self.user2)
    #     self.conversation = Conversation.objects.create(type='private_chat')
    #     self.conversation.members.set([self.user1, self.user2])

    #     # Test case 1: User not logged in
    #     response = self.client.post('/user/create_private_conversation')
    #     self.assertEqual(response.status_code, 401)
    #     self.assertIn("User not logged in", response.content.decode())

    #     # Test case 2: Invalid request body (bad JSON)
    #     response = self.client.post('/user/create_private_conversation', data='{"friend_id": "bad id"}', content_type='application/json', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 400)
    #     self.assertIn("Invalid request", response.content.decode())

    #     # Test case 3: Target user does not exist
    #     response = self.client.post('/user/create_private_conversation', data=json.dumps({'friend_id': 999}), content_type='application/json', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 404)
    #     self.assertIn("Friend not found", response.content.decode())

    #     # Test case 4: No existing friendship
    #     response = self.client.post('/user/create_private_conversation', data=json.dumps({'friend_id': self.user3.id}), content_type='application/json', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 409)
    #     self.assertIn("Not friends", response.content.decode())

    #     # Test case 5: Conversation already exists
    #     response = self.client.post('/user/create_private_conversation', data=json.dumps({'friend_id': self.user2.id}), content_type='application/json', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 200)
    #     data = response.json()
    #     self.assertEqual(data['conversation_id'], self.conversation.id)

    #     # Test case 6: Successfully creating a new conversation
    #     # First, remove the existing conversation to test creation of a new one
    #     self.conversation.delete()
    #     response = self.client.post('/user/create_private_conversation', data=json.dumps({'friend_id': self.user2.id}), content_type='application/json', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 200)
    #     data = response.json()
    #     self.assertTrue(data['conversation_id'] > 0)
    #     self.assertEqual(data['friend_name'], 'user2')

    def test_conversation(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        self.message = Message.objects.create(
            conversation=self.conversation,
            sender=self.user1,
            content="Hello user2!"
        )
        self.message.receivers.add(self.user2)

        # Test case 1: User not logged in
        response = self.client.get(f'/user/conversation/{self.conversation.id}')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Conversation does not exist
        response = self.client.get('/user/conversation/999', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 3: User not in conversation
        response = self.client.get(f'/user/conversation/{self.conversation.id}', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 4: Successfully retrieving messages in the conversation
        response = self.client.get(f'/user/conversation/{self.conversation.id}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)
        self.assertEqual(data['messages'][0]['content'], "Hello user2!")

        # Test case 5: Filtering by sender
        response = self.client.get(f'/user/conversation/{self.conversation.id}?member_id={self.user1.id}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)  # Ensure filter works correctly

        # Test case 6: Invalid member_id
        response = self.client.get(f'/user/conversation/{self.conversation.id}?member_id=999', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 7: Time filtering
        start_time = (timezone.now() - timedelta(hours=1)).isoformat()
        end_time = (timezone.now() + timedelta(hours=1)).isoformat()
        response = self.client.get(f'/user/conversation/{self.conversation.id}?start_time={start_time}&end_time={end_time}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)  # Message should fall within the time range

    def test_send_message(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)

        # Test case 1: User not logged in
        response = self.client.post('/user/send_message', data=json.dumps({"conversation_id": self.conversation.id, "content": "Hello"}), content_type='application/json')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Invalid request (bad JSON)
        response = self.client.post('/user/send_message', data='{"conversation_id": "bad id"}', content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 400)

        # Test case 3: Conversation does not exist
        response = self.client.post('/user/send_message', data=json.dumps({"conversation_id": 999, "content": "Hello"}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 4: User not in conversation
        response = self.client.post('/user/send_message', data=json.dumps({"conversation_id": self.conversation.id, "content": "Hello"}), content_type='application/json', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 5: Successfully sending a message
        # response = self.client.post('/user/send_message', data=json.dumps({"conversation_id": self.conversation.id, "content": "Hello user2"}), content_type='application/json', **self.generate_header("user1"))
        # self.assertEqual(response.status_code, 200)
        # data = response.json()
        # self.assertTrue(data['message_id'] > 0)

        # Ensure the message was created and correctly configured
        # message = Message.objects.get(id=data['message_id'])
        # self.assertEqual(message.content, "Hello user2")
        # self.assertEqual(message.sender, self.user1)
        # self.assertTrue(self.user2 in message.receivers.all())

    def test_delete_message(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        self.message = Message.objects.create(
            conversation=self.conversation,
            sender=self.user1,
            content="Hello user2!"
        )
        self.message.receivers.add(self.user2)

        # Test case 1: User not logged in
        response = self.client.post('/user/delete_message', data=json.dumps({"message_id": self.message.id, "conversation_id": self.conversation.id}), content_type='application/json')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Invalid request (bad JSON)
        response = self.client.post('/user/delete_message', data='{"message_id": "not a number", "conversation_id": "also not a number"}', content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 400)

        # Test case 3: Conversation does not exist
        response = self.client.post('/user/delete_message', data=json.dumps({"message_id": self.message.id, "conversation_id": 999}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 4: Message does not exist in the specified conversation
        wrong_message = Message.objects.create(
            conversation=self.conversation,
            sender=self.user1,
            content="This is a stray message"
        )
        response = self.client.post('/user/delete_message', data=json.dumps({"message_id": wrong_message.id, "conversation_id": self.conversation.id}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)

        # Test case 5: User not in conversation
        response = self.client.post('/user/delete_message', data=json.dumps({"message_id": self.message.id, "conversation_id": self.conversation.id}), content_type='application/json', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 6: Successfully deleting a message
        response = self.client.post('/user/delete_message', data=json.dumps({"message_id": self.message.id, "conversation_id": self.conversation.id}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)

        # Ensure the message is marked as deleted by the user
        self.assertTrue(self.message.deleted_by.filter(pk=self.user1.pk).exists())

    def test_records(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        self.message = Message.objects.create(
            conversation=self.conversation,
            sender=self.user1,
            content="Hello user2!",
            timestamp=timezone.now() - timezone.timedelta(days=1)  # 1 day ago
        )
        self.message.receivers.add(self.user2)

        # Test case 1: User not logged in
        response = self.client.get(f'/user/records/{self.conversation.id}')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Conversation does not exist
        response = self.client.get('/user/records/999', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 3: User not in conversation
        response = self.client.get(f'/user/records/{self.conversation.id}', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 4: Successfully retrieving messages
        response = self.client.get(f'/user/records/{self.conversation.id}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)
        self.assertIn("Hello user2!", data['messages'][0]['content'])

        # Test case 5: Filtering by time range
        start_time = (timezone.now() - timezone.timedelta(days=2)).isoformat()
        end_time = (timezone.now() + timezone.timedelta(days=1)).isoformat()
        response = self.client.get(f'/user/records/{self.conversation.id}?start_time={start_time}&end_time={end_time}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)

        # Test case 6: Filtering by member
        response = self.client.get(f'/user/records/{self.conversation.id}?member_id={self.user1.id}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['messages']), 1)

        # Test case 7: Invalid member ID
        response = self.client.get(f'/user/records/{self.conversation.id}?member_id=999', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

    # def test_mark_as_read(self):
    #     self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
    #     self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
    #     self.conversation = Conversation.objects.create(type='private_chat')
    #     self.conversation.members.add(self.user1, self.user2)
    #     # Create multiple messages
    #     self.messages = [
    #         Message.objects.create(
    #             conversation=self.conversation,
    #             sender=self.user1,
    #             content=f"Message {i}"
    #         ) for i in range(5)
    #     ]

    #     # Test case 1: User not logged in
    #     response = self.client.post(f'/user/mark_as_read/{self.conversation.id}')
    #     self.assertEqual(response.status_code, 401)

    #     # Test case 2: Conversation does not exist
    #     response = self.client.post('/user/mark_as_read/999', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 404)

    #     # Test case 3: User not in conversation
    #     user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
    #     response = self.client.post(f'/user/mark_as_read/{self.conversation.id}', **self.generate_header("user3"))
    #     self.assertEqual(response.status_code, 403)

    #     # Test case 4: Successfully mark messages as read
    #     response = self.client.post(f'/user/mark_as_read/{self.conversation.id}', **self.generate_header("user1"))
    #     self.assertEqual(response.status_code, 200)
    #     for message in self.messages:
    #         message.refresh_from_db()
    #         self.assertTrue(self.user1 in message.read_by.all())

    #     # Test UserConversationStatus updated correctly
    #     status = UserConversationStatus.objects.get(user=self.user1, conversation=self.conversation)
    #     self.assertIsNotNone(status.last_read_at)

    def test_delete_records(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        # Create multiple messages
        self.messages = [
            Message.objects.create(
                conversation=self.conversation,
                sender=self.user1,
                content=f"Message {i}"
            ) for i in range(5)
        ]

        # Test case 1: User not logged in
        response = self.client.post(f'/user/delete_records/{self.conversation.id}')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Conversation does not exist
        response = self.client.post('/user/delete_records/999', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 3: User not in conversation
        user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        response = self.client.post(f'/user/delete_records/{self.conversation.id}', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 4: Successfully mark messages as deleted
        response = self.client.post(f'/user/delete_records/{self.conversation.id}', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        for message in self.messages:
            message.refresh_from_db()
            self.assertTrue(self.user1 in message.deleted_by.all())

    def test_reply_message(self):
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.conversation = Conversation.objects.create(type='private_chat')
        self.conversation.members.add(self.user1, self.user2)
        # Create an initial message to reply to
        self.initial_message = Message.objects.create(
            conversation=self.conversation,
            sender=self.user1,
            content="Initial message"
        )
        
        # Test case 1: User not logged in
        response = self.client.post(f'/user/reply_message', data=json.dumps({"conversation_id": self.conversation.id, "reply_to_id": self.initial_message.id, "content": "Reply"}), content_type='application/json')
        self.assertEqual(response.status_code, 401)

        # Test case 2: Invalid request (bad JSON)
        response = self.client.post('/user/reply_message', data='{"conversation_id": "not a number"}', content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 400)

        # Test case 3: Non-existent conversation
        response = self.client.post('/user/reply_message', data=json.dumps({"conversation_id": 999, "reply_to_id": self.initial_message.id, "content": "Reply"}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 4: Reply to non-existent message
        response = self.client.post('/user/reply_message', data=json.dumps({"conversation_id": self.conversation.id, "reply_to_id": 999, "content": "Reply"}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)

        # Test case 5: User not in conversation
        user_not_in_conversation = CustomUser.objects.create_user(username="user3", password="password3")
        response = self.client.post('/user/reply_message', data=json.dumps({"conversation_id": self.conversation.id, "reply_to_id": self.initial_message.id, "content": "Reply"}), content_type='application/json', **self.generate_header("user3"))
        self.assertEqual(response.status_code, 403)

        # Test case 6: Successfully reply to a message
        # response = self.client.post('/user/reply_message', data=json.dumps({"conversation_id": self.conversation.id, "reply_to_id": self.initial_message.id, "content": "Reply"}), content_type='application/json', **self.generate_header("user1"))
        # self.assertEqual(response.status_code, 200)
        # data = response.json()
        # reply_message = Message.objects.get(id=data['message_id'])
        # self.assertEqual(reply_message.reply_to, self.initial_message)
        # self.assertEqual(reply_message.content, "Reply")
        # self.assertEqual(reply_message.sender, self.user1)

    def test_create_group_conversation(self):
        # Create some test users and friendships
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")  # No friendship with user1
        Friendship.objects.create(user=self.user1, friend=self.user2)

        # Test case 1: User not logged in
        response = self.client.post('/user/create_group_conversation')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/create_group_conversation', data=json.dumps({"name": "Test Group", "members_id": "not_an_array"}), content_type='application/json', **self.generate_header("user4"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: User does not exist
        response = self.client.post('/user/create_group_conversation', data=json.dumps({'name': 'Test Group', 'members_id': [999]}), content_type='application/json', **self.generate_header("user4"))
        self.assertEqual(response.status_code, 404)
        self.assertIn("User does not exist", response.content.decode())

        # Test case 4: Not friends
        response = self.client.post('/user/create_group_conversation', data=json.dumps({'name': 'Test Group', 'members_id': [self.user3.id]}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 409)
        self.assertIn("Not friends", response.content.decode())

        # Test case 5: Member not found
        response = self.client.post('/user/create_group_conversation', data=json.dumps({'name': 'Test Group', 'members_id': [999]}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 404)
        self.assertIn("Member not found", response.content.decode())

        # Test case 6: Successfully creating a new group conversation
        valid_member_ids = [self.user2.id]
        response = self.client.post('/user/create_group_conversation', data=json.dumps({'name': 'Successful Group', 'members_id': valid_member_ids}), content_type='application/json', **self.generate_header("user1"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue('conversation_id' in data)
        self.assertEqual(data['name'], 'Successful Group')
        self.assertIn('members', data)
        self.assertEqual(len(data['members']), 2)  # user1 and user2

    def test_get_group_conversations(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        
        # Create friendships
        Friendship.objects.create(user=self.user1, friend=self.user2)
        Friendship.objects.create(user=self.user2, friend=self.user1)
        
        # Create group conversations
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2])
        self.group2 = Conversation.objects.create(name="Group 2", type='group_chat', is_group=True, owner=self.user1)
        self.group2.members.set([self.user1, self.user3])

        # Generate header with JWT token
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user4 = self.generate_header("user4")  # Non-existent user

        # Test case 1: User not logged in
        response = self.client.get('/user/get_group_conversations')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: User does not exist
        response = self.client.get('/user/get_group_conversations', **self.jwt_header_user4)
        self.assertEqual(response.status_code, 404)
        self.assertIn("User does not exist", response.content.decode())

        # Test case 3: Successfully retrieving group conversations
        response = self.client.get('/user/get_group_conversations', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue('groups' in data)
        self.assertEqual(len(data['groups']), 2)
        
        group_ids = [group['conversation_id'] for group in data['groups']]
        self.assertIn(self.group1.id, group_ids)
        self.assertIn(self.group2.id, group_ids)

    def test_add_admin(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        self.user4 = CustomUser.objects.create_user(username="user4", password="password4")

        # Create friendships
        Friendship.objects.create(user=self.user1, friend=self.user2)
        Friendship.objects.create(user=self.user1, friend=self.user3)
        Friendship.objects.create(user=self.user1, friend=self.user4)

        # Create a group conversation
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])

        # Create another group conversation owned by user4
        self.group2 = Conversation.objects.create(name="Group 2", type='group_chat', is_group=True, owner=self.user4)
        self.group2.members.set([self.user4, self.user3])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user4 = self.generate_header("user4")

        # Test case 1: User not logged in
        response = self.client.post('/user/add_admin')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/add_admin', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': 999, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner)
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group2.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Member not found
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 6: Already owner
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Already owner", response.content.decode())

        # Test case 7: Already admin
        self.group1.admin.add(self.user2)
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Already admin", response.content.decode())

        # Test case 8: Not in group
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user4.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Not in group", response.content.decode())

        # Test case 9: Successfully adding an admin
        response = self.client.post('/user/add_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Admin added successfully")
        self.assertIn(self.user3, self.group1.admin.all())

    def test_remove_admin(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        self.user4 = CustomUser.objects.create_user(username="user4", password="password4")

        # Create friendships
        Friendship.objects.create(user=self.user1, friend=self.user2)
        Friendship.objects.create(user=self.user1, friend=self.user3)
        Friendship.objects.create(user=self.user1, friend=self.user4)

        # Create a group conversation
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])

        # Create another group conversation owned by user4
        self.group2 = Conversation.objects.create(name="Group 2", type='group_chat', is_group=True, owner=self.user4)
        self.group2.members.set([self.user4, self.user3])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user4 = self.generate_header("user4")

        # Test case 1: User not logged in
        response = self.client.post('/user/remove_admin')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/remove_admin', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': 999, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner)
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': self.group2.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Member not found
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 6: Already owner
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Already owner", response.content.decode())

        # Test case 7: Member not admin
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Member not admin", response.content.decode())

        # Test case 8: Successfully removing an admin
        self.group1.admin.add(self.user3)
        response = self.client.post('/user/remove_admin', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Admin removed successfully")
        self.assertNotIn(self.user3, self.group1.admin.all())

    def test_transfer_owner(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        self.user4 = CustomUser.objects.create_user(username="user4", password="password4")

        # Create friendships
        Friendship.objects.create(user=self.user1, friend=self.user2)
        Friendship.objects.create(user=self.user1, friend=self.user3)
        Friendship.objects.create(user=self.user1, friend=self.user4)

        # Create a group conversation
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])

        # Create another group conversation owned by user4
        self.group2 = Conversation.objects.create(name="Group 2", type='group_chat', is_group=True, owner=self.user4)
        self.group2.members.set([self.user4, self.user3])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user4 = self.generate_header("user4")

        # Test case 1: User not logged in
        response = self.client.post('/user/transfer_owner')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/transfer_owner', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': 999, 'new_owner_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner)
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': self.group2.id, 'new_owner_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: New owner not found
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': self.group1.id, 'new_owner_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 6: Already owner
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': self.group1.id, 'new_owner_id': self.user1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 409)
        self.assertIn("Already owner", response.content.decode())

        # Test case 7: New owner not in group
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': self.group1.id, 'new_owner_id': self.user4.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Not in group", response.content.decode())

        # Test case 8: Successfully transferring owner
        response = self.client.post('/user/transfer_owner', data=json.dumps({'group_id': self.group1.id, 'new_owner_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Owner transferred successfully")
        updated_group = Conversation.objects.get(id=self.group1.id)
        self.assertEqual(updated_group.owner, self.user3)

    def test_remove_member(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        self.user4 = CustomUser.objects.create_user(username="user4", password="password4")

        # Create friendships
        Friendship.objects.create(user=self.user1, friend=self.user2)
        Friendship.objects.create(user=self.user1, friend=self.user3)
        Friendship.objects.create(user=self.user1, friend=self.user4)

        # Create a group conversation
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])
        self.group1.admin.set([self.user1, self.user2, self.user3])

        # Create another group conversation owned by user4
        self.group2 = Conversation.objects.create(name="Group 2", type='group_chat', is_group=True, owner=self.user4)
        self.group2.members.set([self.user4, self.user3])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")

        # Test case 1: User not logged in
        response = self.client.post('/user/remove_member')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/remove_member', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': 999, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner or admin)
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group2.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Member not found
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group1.id, 'member_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 6: Cannot remove self
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Cannot remove self", response.content.decode())

        # Test case 7: Cannot remove owner
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user1.id}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Cannot remove owner", response.content.decode())

        # Test case 8: Cannot remove admin
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user3.id}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Cannot remove admin", response.content.decode())

        # Test case 9: Successfully removing member
        response = self.client.post('/user/remove_member', data=json.dumps({'group_id': self.group1.id, 'member_id': self.user2.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Member removed successfully")
        self.assertNotIn(self.user2, self.group1.members.all())

    def test_invite_member(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")
        self.user4 = CustomUser.objects.create_user(username="user4", password="password4")

        # Create a group conversation
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")

        # Test case 1: User not logged in
        response = self.client.post('/user/invite_member')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/invite_member', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/invite_member', data=json.dumps({'group_id': 999, 'invitee_ids': [self.user2.id]}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not member of group)
        response = self.client.post('/user/invite_member', data=json.dumps({'group_id': self.group1.id, 'invitee_ids': [self.user2.id]}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Successfully invite member directly (admin/owner)
        response = self.client.post('/user/invite_member', data=json.dumps({'group_id': self.group1.id, 'invitee_ids': [self.user2.id]}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertIn("Users added directly by admin/owner", data["message"])

        # Test case 6: Successfully invite member through request (non-admin/non-owner)
        response = self.client.post('/user/invite_member', data=json.dumps({'group_id': self.group1.id, 'invitee_ids': [self.user3.id]}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("request_ids", data)
        self.assertTrue(data["request_ids"])

        # Test case 7: Already in group
        response = self.client.post('/user/invite_member', data=json.dumps({'group_id': self.group1.id, 'invitee_ids': [self.user1.id]}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("already_in_group", data)
        self.assertIn(self.user1.username, data["already_in_group"])

    def test_review_invitation(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user3 = self.generate_header("user3")

        # Create invitation requests
        self.invitation_request = Invitation.objects.create(group=self.group1, invitee=self.user2, inviter=self.user1)

        # Test case 1: User not logged in
        response = self.client.post('/user/review_invitation')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/review_invitation', data='{"request_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Invitation request not found
        response = self.client.post('/user/review_invitation', data=json.dumps({'request_id': 999, 'response': 'accept'}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Invitation not found", response.content.decode())

        # Test case 4: User not authorized to review invitation
        response = self.client.post('/user/review_invitation', data=json.dumps({'request_id': self.invitation_request.id, 'response': 'accept'}), content_type='application/json', **self.jwt_header_user3)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Accept invitation
        response = self.client.post('/user/review_invitation', data=json.dumps({'request_id': self.invitation_request.id, 'response': 'accept'}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Invitation.objects.filter(id=self.invitation_request.id, status='accepted').exists())

        # Test case 6: Reject invitation
        response = self.client.post('/user/review_invitation', data=json.dumps({'request_id': self.invitation_request.id, 'response': 'reject'}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Invitation.objects.filter(id=self.invitation_request.id, status='rejected').exists())

    def test_view_invitations(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1])
        self.group1.admin.set([self.user1])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user3 = self.generate_header("user3")

        # Create invitation requests
        self.invitation_request1 = Invitation.objects.create(group=self.group1, invitee=self.user2, inviter=self.user1, status='pending')
        self.invitation_request2 = Invitation.objects.create(group=self.group1, invitee=self.user3, inviter=self.user1, status='rejected')

        # Test case 1: User not logged in
        response = self.client.get(f'/user/view_invitations/{self.group1.id}')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Group not found
        response = self.client.get('/user/view_invitations/999', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 3: User not authorized (not member of group)
        response = self.client.get(f'/user/view_invitations/{self.group1.id}', **self.jwt_header_user3)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 4: Successfully view invitations
        response = self.client.get(f'/user/view_invitations/{self.group1.id}', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("join_requests", data)
        self.assertEqual(len(data["join_requests"]), 2)
        self.assertEqual(data["join_requests"][0]["invitee_id"], self.user2.id)
        self.assertEqual(data["join_requests"][0]["status"], "pending")
        self.assertEqual(data["join_requests"][1]["invitee_id"], self.user3.id)
        self.assertEqual(data["join_requests"][1]["status"], "rejected")

    def test_quit_group(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])
        self.group1.admin.set([self.user1])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")
        self.jwt_header_user3 = self.generate_header("user3")

        # Test case 1: User not logged in
        response = self.client.post('/user/quit_group')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/quit_group', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/quit_group', data=json.dumps({'group_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: Owner cannot quit
        response = self.client.post('/user/quit_group', data=json.dumps({'group_id': self.group1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Owner cannot quit", response.content.decode())

        # Test case 5: Admin quitting group
        response = self.client.post('/user/quit_group', data=json.dumps({'group_id': self.group1.id}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.user2, self.group1.members.all())

        # Test case 6: Member quitting group
        response = self.client.post('/user/quit_group', data=json.dumps({'group_id': self.group1.id}), content_type='application/json', **self.jwt_header_user3)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.user3, self.group1.members.all())

    def test_delete_group(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")
        self.jwt_header_user3 = self.generate_header("user3")

        # Test case 1: User not logged in
        response = self.client.post('/user/delete_group')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/delete_group', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/delete_group', data=json.dumps({'group_id': 999}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner)
        response = self.client.post('/user/delete_group', data=json.dumps({'group_id': self.group1.id}), content_type='application/json', **self.jwt_header_user2)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Successfully delete group
        response = self.client.post('/user/delete_group', data=json.dumps({'group_id': self.group1.id}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Conversation.objects.filter(id=self.group1.id).exists())

    def test_create_group_announcement(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2, self.user3])
        self.group1.admin.set([self.user1])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")
        self.jwt_header_user3 = self.generate_header("user3")

        # Test case 1: User not logged in
        response = self.client.post('/user/create_group_announcement')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Invalid request body (bad JSON)
        response = self.client.post('/user/create_group_announcement', data='{"group_id": "bad id"}', content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid request", response.content.decode())

        # Test case 3: Group not found
        response = self.client.post('/user/create_group_announcement', data=json.dumps({'group_id': 999, 'content': 'Test content'}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 4: User not authorized (not group owner or admin)
        response = self.client.post('/user/create_group_announcement', data=json.dumps({'group_id': self.group1.id, 'content': 'Test content'}), content_type='application/json', **self.jwt_header_user3)
        self.assertEqual(response.status_code, 403)
        self.assertIn("User not authorized", response.content.decode())

        # Test case 5: Empty announcement content
        response = self.client.post('/user/create_group_announcement', data=json.dumps({'group_id': self.group1.id, 'content': ''}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid announcement content", response.content.decode())

        # Test case 6: Successfully create group announcement
        response = self.client.post('/user/create_group_announcement', data=json.dumps({'group_id': self.group1.id, 'content': 'Test announcement'}), content_type='application/json', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("announcement_id", data)
        self.assertIn("content", data)
        self.assertIn("creator", data)
        self.assertIn("create_time", data)


    def test_get_group_announcements(self):
        # Create some test users
        self.user1 = CustomUser.objects.create_user(username="user1", password="password1")
        self.user2 = CustomUser.objects.create_user(username="user2", password="password2")
        self.user3 = CustomUser.objects.create_user(username="user3", password="password3")

        # Create a group conversation owned by user1
        self.group1 = Conversation.objects.create(name="Group 1", type='group_chat', is_group=True, owner=self.user1)
        self.group1.members.set([self.user1, self.user2])

        # Generate headers with JWT tokens
        self.jwt_header_user1 = self.generate_header("user1")
        self.jwt_header_user2 = self.generate_header("user2")
        self.jwt_header_user3 = self.generate_header("user3")

        # Test case 1: User not logged in
        response = self.client.get(f'/user/get_group_announcements/{self.group1.id}')
        self.assertEqual(response.status_code, 401)
        self.assertIn("User not logged in", response.content.decode())

        # Test case 2: Group not found
        response = self.client.get('/user/get_group_announcements/999', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Group not found", response.content.decode())

        # Test case 3: User not in group
        response = self.client.get(f'/user/get_group_announcements/{self.group1.id}', **self.jwt_header_user3)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Not in group", response.content.decode())

        # Test case 4: Successfully get group announcements
        announcement1 = GroupAnnouncement.objects.create(group=self.group1, creator=self.user1, content="Announcement 1")
        announcement2 = GroupAnnouncement.objects.create(group=self.group1, creator=self.user1, content="Announcement 2")
        
        response = self.client.get(f'/user/get_group_announcements/{self.group1.id}', **self.jwt_header_user1)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("announcements", data)
        self.assertEqual(len(data["announcements"]), 2)
        self.assertEqual(data["announcements"][0]["announcement_id"], announcement2.id)
        self.assertEqual(data["announcements"][0]["content"], "Announcement 2")