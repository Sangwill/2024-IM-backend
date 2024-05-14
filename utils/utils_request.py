from django.http import JsonResponse


def request_failed(code, info, status_code=400):
    res =  JsonResponse({
        "code": code,
        "info": info
    }, status=status_code)
    res["Access-Control-Allow-Origin"] = "*"
    return res

def request_success(data={}):
    res = JsonResponse({
        "code": 0,
        "info": "Succeed",
        **data
    },
    status=200)
    res["Access-Control-Allow-Origin"] = "*"
    return res


def return_field(obj_dict, field_list):
    for field in field_list:
        assert field in obj_dict, f"Field `{field}` not found in object."

    return {
        k: v for k, v in obj_dict.items()
        if k in field_list
    }

# 通用
USER_NOT_LOGGED_IN = request_failed(1, "User not logged in", 401)
TARGET_DOES_NOT_EXIST = request_failed(2, "Target does not exist", 404)
METHOD_NOT_ALLOWED = request_failed(-3, "Method Not Allowed", 405)

# 好友
USER_DOES_NOT_EXIST = request_failed(2, "User does not exist")
ALREADY_FRIENDS = request_failed(3, "Already friends")
REAQUEST_ALREADY_SENT = request_failed(4, "Request already sent")
SELF_REQUEST = request_failed(5, "Cannot send request to self")
NOT_FRIENDS = request_failed(3, "Not friends")

# 分组
INVALID_FRIEND_GROUP_NAME = request_failed(2, "Invalid friend group name")
GROUP_NAME_ALREADY_EXISTS = request_failed(3, "Group name already exists")
FRIEND_GROUP_DOES_NOT_EXIST = request_failed(2, "Friend group does not exist")
ALREADY_IN_THIS_FRIEND_GROUP = request_failed(4, "Already in this friend group")
NOT_IN_THIS_FRIEND_GROUP = request_failed(4, "Not in this friend group")

# 会话
USER_NOT_IN_CONVERSATION = request_failed(3, "User not in conversation")
