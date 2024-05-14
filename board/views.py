import re
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from django.http import JsonResponse, HttpRequest, HttpResponse
from django.views.decorators.http import require_http_methods
from django.utils.dateparse import parse_datetime
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from board.models import CustomUser, FriendshipRequest, Friendship, FriendGroup, Conversation, Message, UserConversationStatus, Invitation, GroupAnnouncement
from utils.utils_request import request_failed, request_success
from utils.utils_require import  CheckRequire,  check_for_user_register_data, require, validate_phone, validate_email
from utils.utils_jwt import generate_jwt_token, check_jwt_token
import hashlib

# 通用
USER_NOT_LOGGED_IN = request_failed(1, "User not logged in", 401)
USER_DOES_NOT_EXIST = request_failed(2, "User does not exist", 404)
INVALID_REQUEST = request_failed(3, "Invalid request", 400)

# 管理
USERNAME_ALREADY_EXISTS = request_failed(10, "Username already exists", 409)
INVALID_USERNAME = request_failed(11, "Invalid username", 400)
INVALID_PASSWORD = request_failed(12, "Invalid password", 400)
INVALID_EMAIL = request_failed(13, "Invalid email", 400)
INVALID_PHONE = request_failed(14, "Invalid phone", 400)
INCORRECT_PASSWORD = request_failed(15, "Incorrect password", 403)

# 好友
USER_NOT_FOUND = request_failed(20, "User not found", 404)
REQUEST_NOT_FOUND = request_failed(21, "Request not found", 404)
FRIEND_NOT_FOUND = request_failed(22, "Friend not found", 404)
SELF_REQUEST = request_failed(23, "Cannot send request to self", 400)
ALREADY_FRIENDS = request_failed(24, "Already friends", 409)
REQUEST_ALREADY_SENT = request_failed(25, "Request already sent", 409)
NOT_FRIENDS = request_failed(26, "Not friends", 409)
INVALID_FRIEND_GROUP_NAME = request_failed(27, "Invalid friend group name", 400)

# 会话
CONVERSATION_NOT_FOUND = request_failed(30, "Conversation not found", 404)
MEMBER_NOT_FOUND = request_failed(31, "Member not found", 404)
MESSAGE_NOT_FOUND = request_failed(32, "Message not found", 404)
USER_NOT_IN_CONVERSATION = request_failed(33, "User not in conversation", 403)

# 群聊
GROUP_NOT_FOUND = request_failed(40, "Group not found", 404)
USER_NOT_AUTHORIZED = request_failed(41, "User not authorized", 403)
MEMBER_NOT_ADMIN = request_failed(42, "Member not admin", 403)
NOT_IN_GROUP = request_failed(43, "Not in group", 403)
CANNOT_REMOVE_SELF = request_failed(44, "Cannot remove self", 403)
CANNOT_REMOVE_OWNER = request_failed(45, "Cannot remove owner", 403)
CANNOT_REMOVE_ADMIN = request_failed(46, "Cannot remove admin", 403)
OWNER_CANNOT_QUIT = request_failed(47, "Owner cannot quit", 403)
ALREADY_OWNER = request_failed(48, "Already owner", 409)
ALREADY_ADMIN = request_failed(49, "Already admin", 409)

# 群聊邀请
INVITATION_ALREADY_SENT = request_failed(50, "Invitation already sent", 409)
INVITATION_NOT_FOUND = request_failed(51, "Invitation not found", 404)

# 群公告
INVALID_ANNOUNCEMENT_CONTENT = request_failed(60, "Invalid announcement content", 400)

@CheckRequire
@require_http_methods(["POST"])
def register(req: HttpRequest):
    body = json.loads(req.body.decode("utf-8"))
    
    username, password, email, phone = check_for_user_register_data(body)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    if CustomUser.objects.filter(username=username).exists():
        return USERNAME_ALREADY_EXISTS
    else:
        user = CustomUser(username=username, password=hashed_password, email=email, phone=phone)
        user.save()
        return request_success()

@CheckRequire
@require_http_methods(["POST"])
def login(req: HttpRequest):
    body = json.loads(req.body.decode("utf-8"))
    
    username = require(body, "username", "string", err_msg="Missing or error type of [userName]")
    password = require(body, "password", "string", err_msg="Missing or error type of [password]")
    
    if CustomUser.objects.filter(username=username).exists():
        user = CustomUser.objects.get(username=username)
        if user.password == hashlib.md5(password.encode()).hexdigest():
            return request_success({"token": generate_jwt_token(username),"user_id": user.id})
        else:
            return INCORRECT_PASSWORD
    else:
        return USER_DOES_NOT_EXIST

@require_http_methods(["POST"])
def logoff(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    password = require(body, "password", "string", err_msg="Missing or error type of [password]")
    user= CustomUser.objects.get(username=user_name_jwt["username"])
    if user.password == hashlib.md5(password.encode()).hexdigest():
        CustomUser.objects.filter(username=user).delete()
        return request_success()
    else:
        return INCORRECT_PASSWORD
    
@CheckRequire
@require_http_methods(["PUT"])
def update_normal_info(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    user = CustomUser.objects.get(username=user_name_jwt["username"])
    body = json.loads(req.body.decode("utf-8"))
    avatar= require(body, "avatar_base64", "string", err_msg="Missing or error type of [avatar]")
    user.avatar_base64 = avatar
    user.save()
    return request_success()

@CheckRequire
@require_http_methods(["PUT"])
def update_auth_info(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    username=require(body, "username", "string", err_msg="Missing or error type of [userName]")
    new_password = require(body, "new_password", "string", err_msg="Missing or error type of [new_password]")
    email = require(body, "email", "string", err_msg="Missing or error type of [email]")
    phone = require(body, "phone", "string", err_msg="Missing or error type of [phone]")
    old_password = require(body, "old_password", "string", err_msg="Missing or error type of [old_password]")
    user = CustomUser.objects.get(username=user_name_jwt["username"])
    if user.password == hashlib.md5(old_password.encode()).hexdigest():
        if CustomUser.objects.filter(username=username).exists():
            return USERNAME_ALREADY_EXISTS
        if not len(username) <= 20:
            return INVALID_USERNAME
        user.username = username if len(username) != 0 else user.username
        if not 5<=len(new_password) <= 20 and len(new_password) != 0:
            return INVALID_PASSWORD
        user.password = hashlib.md5(new_password.encode()).hexdigest() if len(new_password) != 0 else user.password
        if not validate_email(email) and not len(email) == 0:
            return INVALID_EMAIL
        user.email = email if len(email) != 0 else user.email
        if not validate_phone(phone) and not len(phone) == 0:
            return INVALID_PHONE
        user.phone = phone if len(phone) != 0 else user.phone
        user.save()
        return request_success()
    else:
        return INCORRECT_PASSWORD

@require_http_methods(["GET"])
def search_friends(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    keyword = req.GET.get("keyword", "")
    matching_users = CustomUser.objects.filter(username__contains=keyword)
    data = [
        {
            "user_id": user.id,
            "username": user.username,
            "avatar_base64": user.avatar_base64
        }
        for user in matching_users
    ]
    return request_success({"data": data})

@require_http_methods(["GET"])
def get_user_profile(req: HttpRequest, username: str):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    try:
        user = CustomUser.objects.get(username=username)
    except CustomUser.DoesNotExist:
        return USER_NOT_FOUND
    is_friend = False
    if(Friendship.objects.filter(user=CustomUser.objects.get(username=user_name_jwt["username"]), friend=user).exists()):
        is_friend = True
    if user_name_jwt["username"] == username:
        is_friend = True
    return request_success({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "avatar_base64": user.avatar_base64,
        "is_friend": is_friend
    })

@require_http_methods(["POST"])
def send_friend_request(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    friend_id = require(body, "friend_id","int", err_msg="Missing or error type of [friend_id]")
    try:
        user = CustomUser.objects.get(username=user_name_jwt["username"])
        friend = CustomUser.objects.get(id=friend_id)
    except CustomUser.DoesNotExist:
        return USER_NOT_FOUND
    if user == friend:
        return SELF_REQUEST
    if Friendship.objects.filter(user=user,friend=friend).exists():
        return ALREADY_FRIENDS
    if FriendshipRequest.objects.filter(user=user,friend=friend).exists():
        if FriendshipRequest.objects.get(user=user, friend=friend).status == 'pending':
            return REQUEST_ALREADY_SENT
        elif FriendshipRequest.objects.get(user=user, friend=friend).status == 'reject':
            FriendshipRequest.objects.filter(user=user, friend=friend).update(status='pending')
            return request_success()
    if FriendshipRequest.objects.filter(user=friend,friend=user,status='pending').exists():
        request = FriendshipRequest.objects.get(user=friend, friend=user)
        Friendship(user=request.user, friend=request.friend).save()
        Friendship(user=request.friend, friend=request.user).save()
        request.status = 'accept'
        request.save()
        request = FriendshipRequest(user=user, friend=friend)
        request.status = 'accept'
        request.save()

        existing_conversations = Conversation.objects.filter(members__in=[user, friend], type='private_chat').prefetch_related('members').distinct()
        for conv in existing_conversations:
            if conv.members.count() == 2 and set(conv.members.all()) == {user, friend}:
                return request_success()
        conversation = Conversation.objects.create(type='private_chat')
        conversation.members.set([user, friend])
        status, created = UserConversationStatus.objects.update_or_create(
            user=user,
            conversation=conversation,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )
        status, created = UserConversationStatus.objects.update_or_create(
            user=friend,
            conversation=conversation,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )

        return request_success()
    request = FriendshipRequest(user=user, friend=friend)
    request.status = 'pending'
    request.save()
    return request_success()

@require_http_methods(["GET"])
def get_friend_requests(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    user = CustomUser.objects.get(username=user_name_jwt["username"])
    requests = FriendshipRequest.objects.filter(friend=user)
    requests = [
        {
            "request_id": request.id,
            "sender_id": request.user.id,
            "sender_name": request.user.username,
            "sender_avatar": request.user.avatar_base64,
            "status": request.status,
            "sent_time": request.create_time.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        }
        for request in requests
    ]
    sent_requests = FriendshipRequest.objects.filter(user=user)
    sent_requests = [
        {
            "request_id": request.id,
            "receiver_id": request.friend.id,
            "receiver_name": request.friend.username,
            "receiver_avatar": request.friend.avatar_base64,
            "status": request.status,
            "sent_time": request.create_time.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        }
        for request in sent_requests
    ]
    return request_success({"requests": requests, "sent_requests": sent_requests})

@require_http_methods(["POST"])
def respond_friend_request(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    request_id = require(body, "request_id", "int", err_msg="Missing or error type of [request_id]")
    response = require(body, "response", "string", err_msg="Missing or error type of [response]")
    try:
        request = FriendshipRequest.objects.get(id=request_id)
    except FriendshipRequest.DoesNotExist:
        return REQUEST_NOT_FOUND
    if response == 'accept':
        user = request.user
        friend = request.friend
        Friendship(user=user, friend=friend).save()
        Friendship(user=friend, friend=user).save()
        request.status = 'accept'

        existing_conversations = Conversation.objects.filter(members__in=[user, friend], type='private_chat').prefetch_related('members').distinct()
        for conv in existing_conversations:
            if conv.members.count() == 2 and set(conv.members.all()) == {user, friend}:
                return request_success()
        conversation = Conversation.objects.create(type='private_chat')
        conversation.members.set([user, friend])
        status, created = UserConversationStatus.objects.update_or_create(
            user=user,
            conversation=conversation,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )
        status, created = UserConversationStatus.objects.update_or_create(
            user=friend,
            conversation=conversation,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )
        
    elif response == 'reject':
        request.status = 'reject'
    request.save()
    return request_success()

@require_http_methods(["POST"])
def delete_friend(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    friend_id = require(body, "friend_id", "int", err_msg="Missing or error type of [friend_id]")
    try:
        user = CustomUser.objects.get(username=user_name_jwt["username"])
        friend = CustomUser.objects.get(id=friend_id)
    except CustomUser.DoesNotExist:
        return FRIEND_NOT_FOUND
    if(not Friendship.objects.filter(user=user, friend=friend).exists()):
        return NOT_FRIENDS
    Friendship.objects.filter(user=user, friend=friend).delete()
    Friendship.objects.filter(user=friend, friend=user).delete()
    if FriendshipRequest.objects.filter(user=user, friend=friend).exists():
        FriendshipRequest.objects.filter(user=user, friend=friend).delete()
    if FriendshipRequest.objects.filter(user=friend, friend=user).exists():
        FriendshipRequest.objects.filter(user=friend, friend=user).delete()
    return request_success()

@require_http_methods(["GET"])
def get_friends(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    user = CustomUser.objects.get(username=user_name_jwt["username"])
    friends = Friendship.objects.filter(user=user)

    # 创建一个字典来组织分组
    groups = {}
    for friend in friends:
        group_name = friend.friend_group.name if friend.friend_group is not None else ""
        if group_name not in groups:
            groups[group_name] = []
        groups[group_name].append({
            "friend_id": friend.friend.id,
            "friend_name": friend.friend.username,
            "friend_avatar": friend.friend.avatar_base64
        })

    # 构建分组列表
    all_groups = [{"group_name": group_name, "group_friends": friends} for group_name, friends in groups.items()]

    return request_success({"groups": all_groups})


@require_http_methods(["POST"])
def add_friend_to_friend_group(req: HttpRequest):
    jwt_token = req.headers.get("Authorization")
    user_name_jwt = check_jwt_token(jwt_token)
    if user_name_jwt is None:
        return USER_NOT_LOGGED_IN
    body = json.loads(req.body.decode("utf-8"))
    friend_group_name = require(body, "friend_group_name", "string", err_msg="Missing or error type of [group_id]")
    if not len(friend_group_name)<=20:
        return INVALID_FRIEND_GROUP_NAME
    friend_id = require(body, "friend_id", "int", err_msg="Missing or error type of [friend_id]")
    user = CustomUser.objects.get(username=user_name_jwt["username"])
    try:
        friend = CustomUser.objects.get(id=friend_id)
    except CustomUser.DoesNotExist:
        return NOT_FRIENDS
    if not Friendship.objects.filter(user=user, friend=friend).exists():
        return NOT_FRIENDS
    if not FriendGroup.objects.filter(user=user, name=friend_group_name).exists():
        if friend_group_name == "":
            Friendship.objects.filter(user=user, friend=friend).update(friend_group=None)
            return request_success()
        friend_group = FriendGroup(user=user, name=friend_group_name)
        friend_group.save()
        Friendship.objects.filter(user=user, friend=friend).update(friend_group=friend_group)
    else:
        friend_group = FriendGroup.objects.get(user=user, name=friend_group_name)
        Friendship.objects.filter(user=user, friend=friend).update(friend_group=friend_group)
    return request_success()


# 会话基本功能

@require_http_methods(["GET"])
def get_private_conversations(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    # 获取用户的私人聊天
    try:
        user = CustomUser.objects.get(username=user_data["username"])
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST
    
    conversations = Conversation.objects.filter(members=user, type='private_chat').prefetch_related('members')
    result_conversations = []
    for conv in conversations:
        for member in conv.members.all():
            if member != user:
                unread_count = Message.objects.filter(conversation=conv, receivers=user).exclude(sender=user).exclude(read_by=user).count()
                result_conversations.append({
                    "conversation_id": conv.id,
                    "is_group": False,
                    "friend_id": member.id,
                    "name": member.username,
                    "friend_avatar": member.avatar_base64,
                    "unread_count": unread_count
                })
                break  # 只取第一个不是当前用户的成员
    
    return request_success({"conversations": result_conversations})



@require_http_methods(["POST"])
def create_private_conversation(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    # jwt_token = request.headers.get("Authorization")
    # user_data = check_jwt_token(jwt_token)
    # if user_data is None:
    #     return USER_NOT_LOGGED_IN
    
    # # 分析请求体
    # try:
    #     body = json.loads(request.body)
    #     friend_id = int(body.get('friend_id'))
    # except (json.JSONDecodeError, ValueError, TypeError):
    #     return INVALID_REQUEST
    
    # # 验证 friend_id 的合法性
    # try:
    #     requester = CustomUser.objects.get(username=user_data["username"])
    #     friend = CustomUser.objects.get(pk=friend_id)
    # except CustomUser.DoesNotExist:
    #     return FRIEND_NOT_FOUND
    
    # if not Friendship.objects.filter(user=requester, friend=friend).exists():
    #     return NOT_FRIENDS
    
    # # 检查是否已存在私人聊天
    # existing_conversations = Conversation.objects.filter(members__in=[requester, friend], type='private_chat').prefetch_related('members').distinct()
    # for conv in existing_conversations:
    #     if conv.members.count() == 2 and set(conv.members.all()) == {requester, friend}:
    #         # 找到了一个已存在的私人聊天，直接返回
    #             return request_success({
    #                 "conversation_id": conv.id,
    #                 "friend_id": friend_id,
    #                 "friend_name": friend.username,
    #                 "friend_avatar": friend.avatar_base64
    #             })
        
    # conversation = Conversation.objects.create(type='private_chat')
    # conversation.members.set([requester, friend])
    # status, created = UserConversationStatus.objects.update_or_create(
    #     user=requester,
    #     conversation=conversation,
    #     defaults={
    #         'last_read_at': datetime.now(timezone(timedelta(hours=8))),
    #         'last_read_message_id': 0
    #     },
    # )
    # status, created = UserConversationStatus.objects.update_or_create(
    #     user=friend,
    #     conversation=conversation,
    #     defaults={
    #         'last_read_at': datetime.now(timezone(timedelta(hours=8))),
    #         'last_read_message_id': 0
    #     },
    # )
    return request_success({
        # "conversation_id": conversation.id, 
        # "friend_id": friend_id,
        # "friend_name": friend.username,
        # "friend_avatar": friend.avatar_base64
        })


@require_http_methods(["GET"])
def conversation(request: HttpRequest, conversation_id: int) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    # 验证 conversation_id 的合法性
    try:
        conversation = Conversation.objects.get(id=conversation_id)
    except Conversation.DoesNotExist:
        return CONVERSATION_NOT_FOUND
    
    # 验证用户是否是 conversation 的成员
    try:
        user = CustomUser.objects.get(username=user_data["username"])
    except CustomUser.DoesNotExist:
        return MEMBER_NOT_FOUND
    
    if not conversation.members.filter(pk=user.pk).exists():
        return USER_NOT_IN_CONVERSATION
    
    if Message.objects.filter(conversation=conversation):
        last_read_message_id = Message.objects.filter(conversation=conversation).last().id
    else:
        last_read_message_id = 0

    status, created = UserConversationStatus.objects.update_or_create(
        user=user,
        conversation=conversation,
        defaults={
            'last_read_at': datetime.now(timezone(timedelta(hours=8))),
            'last_read_message_id': last_read_message_id
        },
    )
    
    messages = Message.objects.filter(conversation=conversation)
    for msg in messages:
        msg.read_by.add(user)

    last_read_map = {}
    for member in conversation.members.all():
        # 查询每个成员在当前会话中的状态
        status = UserConversationStatus.objects.filter(
            user=member,
            conversation=conversation
        ).first()  # 使用 first() 是因为 unique_together 确保了每对会有唯一的记录
        
        # 将成员 ID 与 最后阅读消息 ID 存入字典
        last_read_map[member.id] = status.last_read_message_id if status else None

    channel_layer = get_channel_layer()
    for member in conversation.members.all():
        async_to_sync(channel_layer.group_send)(
            member.username, 
            {
                'type': 'read',
                'conversation_id': conversation_id,
                'unread_count': 0,
                'last_read_map': last_read_map,
            }
        )

    start_time = request.GET.get("start_time")
    end_time = request.GET.get("end_time")
    member_id = request.GET.get("member_id")

    if start_time:
        start_time = parse_datetime(start_time)
    if end_time:
        end_time = parse_datetime(end_time)

    messages_query = Message.objects.filter(conversation=conversation).exclude(deleted_by=user).order_by('timestamp')

    if start_time:
        messages_query = messages_query.filter(timestamp__gte=start_time)
    if end_time:
        messages_query = messages_query.filter(timestamp__lte=end_time)
    if member_id:
        try:
            member = CustomUser.objects.get(pk=member_id)
            messages_query = messages_query.filter(sender=member)
        except CustomUser.DoesNotExist:
            return MEMBER_NOT_FOUND
        
    messages = messages_query.select_related('sender').prefetch_related('receivers')

    return request_success({
"members": [
    {
        "member_id": member.id,
        "member_name": member.username,
        "member_avatar": member.avatar_base64,
    }
    for member in conversation.members.all()
],
"last_read_map": last_read_map,
"messages": [
    {
        "conversation_id": conversation.id,
        "msg_id": msg.id,
        "content": msg.content,
        "sender_id": msg.sender.id,
        "create_time": msg.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
        "reply_count": msg.reply_count,
        "reply_to": {
            "msg_id": msg.reply_to.id,
            "content": msg.reply_to.content,
            "sender_id": msg.reply_to.sender.id,
            "create_time": msg.reply_to.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
        } if msg.reply_to else None
    }
    for msg in messages
]
    })

@require_http_methods(["POST"])
def send_message(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 分析请求体
    try:
        body = json.loads(request.body)
        conversation_id = int(body.get("conversation_id"))
        content = body.get("content", "").strip()
    except (ValueError, TypeError, AttributeError):
        return INVALID_REQUEST

    # 验证 conversation_id 和 content 的合法性
    try:
        conversation = Conversation.objects.prefetch_related('members').get(id=conversation_id)
    except Conversation.DoesNotExist:
        return CONVERSATION_NOT_FOUND
    
    # 验证 sender 是否是 conversation 的成员
    try:
        sender = CustomUser.objects.get(username=user_data["username"])
    except CustomUser.DoesNotExist:
        return MEMBER_NOT_FOUND
    
    if not conversation.members.filter(pk=sender.pk).exists():
        return USER_NOT_IN_CONVERSATION

    if not conversation.is_group:  
        receiver = conversation.members.exclude(pk=sender.pk).first()
        if not receiver:
            return MEMBER_NOT_FOUND
        if not Friendship.objects.filter(user=sender, friend=receiver).exists():
            return NOT_FRIENDS

    message = Message.objects.create(
        conversation=conversation,
        sender=sender,
        content=content
    )

    message.receivers.set(conversation.members.all())

    status, created = UserConversationStatus.objects.update_or_create(
        user=sender,
        conversation=conversation,
        defaults={
            'last_read_at': datetime.now(timezone(timedelta(hours=8))),
            'last_read_message_id': message.id
        },
    )

    messages = Message.objects.filter(conversation=conversation)
    for msg in messages:
        msg.read_by.add(sender)

    last_read_map = {}
    for member in conversation.members.all():
        # 查询每个成员在当前会话中的状态
        status = UserConversationStatus.objects.filter(
            user=member,
            conversation=conversation
        ).first()  # 使用 first() 是因为 unique_together 确保了每对会有唯一的记录
        
        # 将成员 ID 与 最后阅读消息 ID 存入字典
        last_read_map[member.id] = status.last_read_message_id if status else None
    
    channel_layer = get_channel_layer()
    for member in conversation.members.all():
        async_to_sync(channel_layer.group_send)(
            member.username, 
            {
                'type': 'notify',
                'conversation_id': conversation_id,
                'sender_id': sender.id,
                "sender_name": sender.username,
                "sender_avatar": sender.avatar_base64,
                'message_id': message.id,
                'content': content,
                'timestamp': message.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
                'unread_count': UserConversationStatus.objects.filter(conversation=conversation, user=member).first().unread_count,
                'last_read_map': last_read_map,
                'reply_to': None,
            }
        )

    return request_success({"message_id": message.id})


@require_http_methods(["POST"])
def delete_message(request: HttpRequest) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        body = json.loads(request.body)
        message_id = int(body.get("message_id"))
        conversation_id = int(body.get("conversation_id"))
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return INVALID_REQUEST

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        conversation = Conversation.objects.get(id=conversation_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return CONVERSATION_NOT_FOUND
    
    if not conversation.members.filter(pk=user.pk).exists():
        return USER_NOT_IN_CONVERSATION

    message = Message.objects.get(id=message_id, conversation=conversation)
    message.deleted_by.add(user)

    return request_success()

@require_http_methods(["GET"])
def records(request: HttpRequest, conversation_id: int) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    # 验证 conversation_id 的合法性
    try:
        conversation = Conversation.objects.get(id=conversation_id)
    except Conversation.DoesNotExist:
        return CONVERSATION_NOT_FOUND
    
    # 验证用户是否是 conversation 的成员
    try:
        user = CustomUser.objects.get(username=user_data["username"])
    except CustomUser.DoesNotExist:
        return MEMBER_NOT_FOUND
    
    if not conversation.members.filter(pk=user.pk).exists():
        return USER_NOT_IN_CONVERSATION
    
    start_time = request.GET.get("start_time")
    end_time = request.GET.get("end_time")
    member_id = request.GET.get("member_id")

    if start_time:
        start_time = parse_datetime(start_time)
    if end_time:
        end_time = parse_datetime(end_time)

    messages_query = Message.objects.filter(conversation=conversation).exclude(deleted_by=user).order_by('timestamp')

    if start_time:
        messages_query = messages_query.filter(timestamp__gte=start_time)
    if end_time:
        messages_query = messages_query.filter(timestamp__lte=end_time)
    if member_id:
        try:
            member = CustomUser.objects.get(pk=member_id)
            messages_query = messages_query.filter(sender=member)
        except CustomUser.DoesNotExist:
            return MEMBER_NOT_FOUND
        
    messages = messages_query.select_related('sender').prefetch_related('receivers')

    return request_success({"messages": [
        {
            "msg_id": msg.id,
            "content": msg.content,
            "sender_id": msg.sender.id,
            "sender_name": msg.sender.username,
            "sender_avatar": msg.sender.avatar_base64,
            "create_time": msg.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for msg in messages
    ]})

@require_http_methods(["POST"])
def mark_as_read(request: HttpRequest, conversation_id: int) -> HttpResponse:
    # jwt_token = request.headers.get("Authorization")
    # user_data = check_jwt_token(jwt_token)
    # if user_data is None:
    #     return USER_NOT_LOGGED_IN
    
    # try:
    #     user = CustomUser.objects.get(username=user_data["username"])
    #     conversation = Conversation.objects.get(id=conversation_id)
    # except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
    #     return CONVERSATION_NOT_FOUND
    
    # if not conversation.members.filter(pk=user.pk).exists():
    #     return USER_NOT_IN_CONVERSATION
    
    # if Message.objects.filter(conversation=conversation):
    #     last_read_message_id = Message.objects.filter(conversation=conversation).last().id
    # else:
    #     last_read_message_id = 0

    # status, created = UserConversationStatus.objects.update_or_create(
    #     user=user,
    #     conversation=conversation,
    #     defaults={
    #         'last_read_at': datetime.now(timezone(timedelta(hours=8))),
    #         'last_read_message_id': last_read_message_id
    #     },
    # )
    
    # messages = Message.objects.filter(conversation=conversation)
    # for msg in messages:
    #     msg.read_by.add(user)
    
    return request_success()

@require_http_methods(["POST"])
def delete_records(request: HttpRequest, conversation_id: int) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    try:
        user = CustomUser.objects.get(username=user_data["username"])
        conversation = Conversation.objects.get(id=conversation_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return CONVERSATION_NOT_FOUND
    
    if not conversation.members.filter(pk=user.pk).exists():
        return USER_NOT_IN_CONVERSATION

    messages = Message.objects.filter(conversation=conversation)
    for msg in messages:
        msg.deleted_by.add(user)

    return request_success()

@require_http_methods(["POST"])
def reply_message(request: HttpRequest) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        body = json.loads(request.body)
        conversation_id = int(body.get("conversation_id"))
        reply_to_id = int(body.get("reply_to_id"))
        content = body.get("content", "").strip()
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return INVALID_REQUEST

    try:
        sender = CustomUser.objects.get(username=user_data["username"])
        conversation = Conversation.objects.get(id=conversation_id)
        reply_to_message = Message.objects.get(id=reply_to_id, conversation=conversation)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist, Message.DoesNotExist):
        return MESSAGE_NOT_FOUND
    
    if not conversation.members.filter(pk=sender.pk).exists():
        return USER_NOT_IN_CONVERSATION

    message = Message.objects.create(
        conversation=conversation,
        sender=sender,
        content=content,
        reply_to=reply_to_message
    )

    message.receivers.set(conversation.members.all())

    status, created = UserConversationStatus.objects.update_or_create(
        user=sender,
        conversation=conversation,
        defaults={
            'last_read_at': datetime.now(timezone(timedelta(hours=8))),
            'last_read_message_id': message.id
        },
    )

    messages = Message.objects.filter(conversation=conversation)
    for msg in messages:
        msg.read_by.add(sender)

    last_read_map = {}
    for member in conversation.members.all():
        # 查询每个成员在当前会话中的状态
        status = UserConversationStatus.objects.filter(
            user=member,
            conversation=conversation
        ).first()  # 使用 first() 是因为 unique_together 确保了每对会有唯一的记录
        
        # 将成员 ID 与 最后阅读消息 ID 存入字典
        last_read_map[member.id] = status.last_read_message_id if status else None

    channel_layer = get_channel_layer()
    for member in conversation.members.all():
        async_to_sync(channel_layer.group_send)(
            member.username, 
            {
                'type': 'notify',
                'conversation_id': conversation_id,
                'sender_id': sender.id,
                "sender_name": sender.username,
                "sender_avatar": sender.avatar_base64,
                'message_id': message.id,
                'content': message.content,
                'timestamp': message.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
                'unread_count': UserConversationStatus.objects.filter(conversation=conversation, user=member).first().unread_count,
                'last_read_map': last_read_map,
                'reply_to': {
                    "msg_id": message.reply_to.id,
                    "content": message.reply_to.content,
                    "sender_id": message.reply_to.sender.id,
                    "sender_name": message.reply_to.sender.username,
                    "sender_avatar": message.reply_to.sender.avatar_base64,
                    "timestamp": message.reply_to.timestamp.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S"),
                }
            }
        )

    return request_success({"message_id": message.id})

@require_http_methods(["POST"])
def create_group_conversation(request: HttpRequest) -> JsonResponse:
    # 验证用户是否登录并获取其数据
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体获取群聊相关数据
    try:
        body = json.loads(request.body)
        name = body.get('name', '').strip()
        members_ids = body.get('members_id', [])
        if not isinstance(members_ids, list):
            return INVALID_REQUEST  # 如果不是列表，返回无效请求
        members_ids = set(members_ids)  # 使用集合来避免重复成员ID

    except (json.JSONDecodeError, ValueError):
        return INVALID_REQUEST

    # 验证发起请求的用户是否存在，并确保群主包含在成员列表中
    try:
        owner = CustomUser.objects.get(username=user_data['username'])
        members_ids.add(owner.id)  # 确保群主是成员之一
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST

    # 验证成员ID并添加到会话
    members = CustomUser.objects.filter(id__in=members_ids)
    if len(members_ids) != members.count():
        return MEMBER_NOT_FOUND
    
    # 验证所选成员是否为当前用户的好友
    if not all(Friendship.objects.filter(user=owner, friend=member).exists() for member in members if member != owner):
        return NOT_FRIENDS

    # 创建群聊会话
    group = Conversation.objects.create(
        name=name,
        is_group=True,
        type='group_chat',
        owner=owner
    )
    group.members.set(members)  # 设置会话成员

    for member in members:
        status, created = UserConversationStatus.objects.update_or_create(
            user=member,
            conversation=group,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )

    # 设置管理员
    # group.admin.set([owner])

    # 返回成功创建的群聊信息
    return request_success({
        'conversation_id': group.id,
        'name': group.name,
        'members': list(members.values('id', 'username')),
        'owner_id': owner.id
    })

@require_http_methods(["GET"])
def get_group_conversations(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    # 获取用户的群聊
    try:
        user = CustomUser.objects.get(username=user_data["username"])
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST
    
    groups = Conversation.objects.filter(members=user, type='group_chat').prefetch_related('members')
    result_groups = []
    for group in groups:
        member_details = []
        for member in group.members.all():
            unread_count = Message.objects.filter(conversation=group, receivers=user).exclude(sender=user).exclude(read_by=user).count()
            member_details.append({
                "member_id": member.id,
                "member_name": member.username,
                "member_avatar": member.avatar_base64
            })

        result_groups.append({
            "conversation_id": group.id,
            "is_group": True,
            "name": group.name,
            "members": member_details,
            "owner_id": group.owner.id,
            "admins_ids": [admin.id for admin in group.admin.all()],
            "unread_count": unread_count
        })
    
    return request_success({"groups": result_groups})

@require_http_methods(["POST"])
def add_admin(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    # 解析请求体
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST
        member_id = body.get('member_id')
        if not isinstance(member_id, int):
            return INVALID_REQUEST
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和会话
    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id)
        if user != group.owner:
            return USER_NOT_AUTHORIZED
        member = CustomUser.objects.get(id=member_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    # 检查成员是否已经是群主
    if member == user:
        return ALREADY_OWNER

    # 检查成员是否已经是管理员
    if member in group.admin.all():
        return ALREADY_ADMIN

    # 添加管理员
    if member in group.members.all():
        group.admin.add(member)
        return request_success({"message": "Admin added successfully"})
    else:
        return NOT_IN_GROUP

@require_http_methods(["POST"])
def remove_admin(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST
        member_id = body.get('member_id')
        if not isinstance(member_id, int):
            return INVALID_REQUEST
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和会话
    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id)
        if user != group.owner:
            return USER_NOT_AUTHORIZED
        member = CustomUser.objects.get(id=member_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    # 检查成员是否已经是群主
    if member == group.owner:
        return ALREADY_OWNER

    # 检查成员是否是管理员
    if member not in group.admin.all():
        return MEMBER_NOT_ADMIN
    
    # 移除管理员
    if member in group.admin.all():
        group.admin.remove(member)
        return request_success({"message": "Admin removed successfully"})
    else:
        return NOT_IN_GROUP

@require_http_methods(["POST"])
def transfer_owner(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST
        new_owner_id = body.get('new_owner_id')
        if not isinstance(new_owner_id, int):
            return INVALID_REQUEST
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和会话
    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id)
        if user != group.owner:
            return USER_NOT_AUTHORIZED
        new_owner = CustomUser.objects.get(id=new_owner_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    # 检查新群主是否已经是群主
    if new_owner == group.owner:
        return ALREADY_OWNER

    # 检查新群主是否是管理员
    if new_owner in group.admin.all():
        group.admin.remove(new_owner)

    # 转让群主
    if new_owner in group.members.all():
        group.owner = new_owner
        group.save()
        return request_success({"message": "Owner transferred successfully"})
    else:
        return NOT_IN_GROUP

@require_http_methods(["POST"])
def remove_member(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST
        member_id = body.get('member_id')
        if not isinstance(member_id, int):
            return INVALID_REQUEST
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和会话
    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id)
        if user != group.owner and user not in group.admin.all():
            return USER_NOT_AUTHORIZED
        member = CustomUser.objects.get(id=member_id)
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    if member not in group.members.all():
        return NOT_IN_GROUP

    # 检查成员是否是群主或管理员
    if user == group.owner:
        if member == group.owner:
            return CANNOT_REMOVE_SELF
        if member in group.admin.all():
            group.admin.remove(member)
    else:
        if user == member:
            return CANNOT_REMOVE_SELF
        if member == group.owner:
            return CANNOT_REMOVE_OWNER
        if member in group.admin.all():
            return CANNOT_REMOVE_ADMIN

    # 移除成员
    group.members.remove(member)
    return request_success({"message": "Member removed successfully"})

@require_http_methods(["POST"])
def invite_member(request: HttpRequest) -> HttpResponse:
    # 验证用户是否登录
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST
        invitee_ids = body.get('invitee_ids')  # 改为接收多个被邀请者ID
        if not isinstance(invitee_ids, list):  # 确保是列表
            return INVALID_REQUEST
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和会话
    try:
        inviter = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND
    
    if not group.members.filter(pk=inviter.pk).exists():
        return USER_NOT_AUTHORIZED

    if inviter == group.owner or inviter in group.admin.all():
        # 为每个被邀请者ID添加成员
        added_users = []
        already_in_group = []
        for invitee_id in invitee_ids:
            try:
                invitee = CustomUser.objects.get(id=invitee_id)
                if group.members.filter(pk=invitee.pk).exists():
                    already_in_group.append(invitee.username)  # 用户已在群聊中
                else:
                    group.members.add(invitee)
                    added_users.append(invitee.username)  # 收集成功添加的用户名
                    status, created = UserConversationStatus.objects.update_or_create(
                        user=invitee,
                        conversation=group,
                        defaults={
                            'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                            'last_read_message_id': 0
                        },
                    )
            except CustomUser.DoesNotExist:
                continue  # 如果用户不存在，继续处理下一个ID
        return request_success({
            "message": f"Users added directly by admin/owner: {added_users}",
            "already_in_group": already_in_group
        })
    else:
        # 如果不是群主或管理员，创建审批请求
        requests_created = []
        already_in_group = []
        invitations_already_sent = []
        for invitee_id in invitee_ids:
            try:
                invitee = CustomUser.objects.get(id=invitee_id)
                if group.members.filter(pk=invitee.pk).exists():
                    already_in_group.append(invitee.username)  # 用户已在群聊中
                elif Invitation.objects.filter(group=group, invitee=invitee).exists():
                    invitations_already_sent.append(invitee.username)  # 已发送邀请
                else:
                    join_request = Invitation.objects.create(group=group, invitee=invitee, inviter=inviter)
                    requests_created.append(join_request.id)  # 收集创建的请求ID
            except CustomUser.DoesNotExist:
                continue
        return request_success({
            "request_ids": requests_created,
            "already_in_group": already_in_group,
            "invitations_already_sent": invitations_already_sent
        })


@require_http_methods(["POST"])
def review_invitation(request: HttpRequest) -> HttpResponse:
    # 确认用户登录状态
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    # 解析请求体
    try:
        body = json.loads(request.body)
        request_id = body.get('request_id')
        if not isinstance(request_id, int):
            return INVALID_REQUEST
        response = body.get('response')
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    # 检查用户和邀请
    try:
        reviewer = CustomUser.objects.get(username=user_data["username"])
        join_request = Invitation.objects.get(id=request_id)
    except CustomUser.DoesNotExist:
        return USER_NOT_FOUND
    except Invitation.DoesNotExist:
        return INVITATION_NOT_FOUND

    # 核实用户权限
    if reviewer != join_request.group.owner and reviewer not in join_request.group.admin.all():
        return USER_NOT_AUTHORIZED

    # 处理邀请响应
    if response == 'accept':
        join_request.group.members.add(join_request.invitee)
        status, created = UserConversationStatus.objects.update_or_create(
            user=join_request.invitee,
            conversation=join_request.group,
            defaults={
                'last_read_at': datetime.now(timezone(timedelta(hours=8))),
                'last_read_message_id': 0
            },
        )
        join_request.delete()
    elif response == 'reject':
        join_request.delete()
    else:
        return INVALID_REQUEST

    return request_success()

@require_http_methods(["GET"])
def view_invitations(request: HttpRequest, group_id: int) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST
    except Conversation.DoesNotExist:
        return GROUP_NOT_FOUND

    if user != group.owner and user not in group.admin.all():
        return USER_NOT_AUTHORIZED

    join_requests = Invitation.objects.filter(group=group).select_related('invitee', 'inviter')
    requests_data = [
        {
            "request_id": join_request.id,
            "invitee_id": join_request.invitee.id,
            "invitee_name": join_request.invitee.username,
            "inviter_id": join_request.inviter.id,
            "inviter_name": join_request.inviter.username,
            "status": join_request.status,
            "created_at": join_request.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for join_request in join_requests
    ]

    return request_success({"join_requests": requests_data})

@require_http_methods(["POST"])
def quit_group(request: HttpRequest) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN
    
    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST     
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST
    except Conversation.DoesNotExist:
        return GROUP_NOT_FOUND

    if user == group.owner:
        return OWNER_CANNOT_QUIT

    if user in group.admin.all():
        group.admin.remove(user)

    if user in group.members.all():
        group.members.remove(user)
        return request_success()
    else:
        return NOT_IN_GROUP

@require_http_methods(["POST"])
def delete_group(request: HttpRequest) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST   
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except CustomUser.DoesNotExist:
        return USER_DOES_NOT_EXIST
    except Conversation.DoesNotExist:
        return GROUP_NOT_FOUND

    if user != group.owner:
        return USER_NOT_AUTHORIZED

    group.delete()
    return request_success()

@require_http_methods(["POST"])
def create_group_announcement(request: HttpRequest) -> HttpResponse:
    jwt_token = request.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        body = json.loads(request.body)
        group_id = body.get('group_id')
        if not isinstance(group_id, int):
            return INVALID_REQUEST   
        content = body.get('content')
    except (ValueError, json.JSONDecodeError):
        return INVALID_REQUEST

    if not content.strip():
        return INVALID_ANNOUNCEMENT_CONTENT

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    if user != group.owner and user not in group.admin.all():
        return USER_NOT_AUTHORIZED

    announcement = GroupAnnouncement.objects.create(
        group=group,
        creator=user,
        content=content
    )

    return request_success({
        "announcement_id": announcement.id,
        "content": announcement.content,
        "creator": {"id": user.id, "username": user.username},
        "create_time": announcement.create_time.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    })

@require_http_methods(["GET"])
def get_group_announcements(req: HttpRequest, group_id: int):
    jwt_token = req.headers.get("Authorization")
    user_data = check_jwt_token(jwt_token)
    if user_data is None:
        return USER_NOT_LOGGED_IN

    try:
        user = CustomUser.objects.get(username=user_data["username"])
        group = Conversation.objects.get(id=group_id, type='group_chat')
    except (CustomUser.DoesNotExist, Conversation.DoesNotExist):
        return GROUP_NOT_FOUND

    if not group.members.filter(pk=user.pk).exists():
        return NOT_IN_GROUP

    announcements_query = GroupAnnouncement.objects.filter(group=group).order_by('-create_time')

    announcements = [
        {
            "announcement_id": announcement.id,
            "content": announcement.content,
            "creator": {
                "id": announcement.creator.id,
                "username": announcement.creator.username
            },
            "create_time": announcement.create_time.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        }
        for announcement in announcements_query
    ]

    return request_success({"announcements": announcements})