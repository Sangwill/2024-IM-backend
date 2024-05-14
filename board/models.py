from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# 导入其它必需模块
from utils.utils_require import  default_avatar



# 自定义用户模型
class CustomUser(AbstractUser):
    id = models.BigAutoField(primary_key=True)
    avatar_base64 = models.TextField(null=True,default=default_avatar)
    phone = models.CharField(max_length=20, null=True, blank=True)
    # 可以根据需要添加更多字段

    class Meta:
        indexes = [models.Index(fields=["username"])]  # 使用 username 作为示例，因为 username 字段被 AbstractUser 中的 username 字段代替

# 好友分组模型
class FriendGroup(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=20)

    class Meta:
        unique_together = ("name", "user")

# 好友关系模型
class Friendship(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="user_friendship")
    friend = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="friend_friendship")
    friend_group = models.ForeignKey(FriendGroup, on_delete=models.SET_NULL, related_name="friend_group", null=True)

    class Meta:
        unique_together = ("user", "friend")

# 好友请求模型
class FriendshipRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accept', 'Accept'),
        ('reject', 'Reject'),
    )
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="user_friendship_request")
    friend = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="friend_friendship_request")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    create_time = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ("user", "friend")

# 对话模型
class Conversation(models.Model):
    # 基本信息
    id = models.BigAutoField(primary_key=True)
    members = models.ManyToManyField(CustomUser, related_name='conversations')
    name = models.CharField(max_length=20, null=True, blank=True)
    avatar_base64 = models.TextField(null=True)
    # 时间信息
    create_time = models.DateTimeField(auto_now_add=True)
    update_time = models.DateTimeField(auto_now=True)
    # 类型信息
    is_group = models.BooleanField(default=False)
    TYPE_CHOICES = [
        ('private_chat', 'Private Chat'),
        ('group_chat', 'Group Chat'),
    ]
    type = models.CharField(max_length=12, choices=TYPE_CHOICES)
    # 群聊管理信息
    owner = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='conversation_owner')
    admin = models.ManyToManyField(CustomUser, related_name="conversation_admin")

# 消息模型
class Message(models.Model):
    # 基本信息
    id = models.BigAutoField(primary_key=True)
    conversation = models.ForeignKey(Conversation, related_name='messages', on_delete=models.CASCADE, null=True, blank=True)
    sender = models.ForeignKey(CustomUser, related_name='sent_messages', on_delete=models.CASCADE)
    receivers = models.ManyToManyField(CustomUser, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    # 状态信息
    read_by = models.ManyToManyField(CustomUser, related_name='read_messages', blank=True)
    deleted_by = models.ManyToManyField(CustomUser, related_name='deleted_messages', blank=True)
    # 回复信息
    reply_to = models.ForeignKey('self', related_name='replies', on_delete=models.SET_NULL, null=True, blank=True)
    reply_count = models.IntegerField(default=0)
    
    def save(self, update_reply_count=True, *args, **kwargs):
        if self.reply_to and update_reply_count:
            # 如果是回复别的消息，更新那条消息的回复计数
            parent_msg = Message.objects.get(id=self.reply_to.id)
            parent_msg.reply_count += 1
            parent_msg.save(update_reply_count=False)  # 阻止递归更新
        super(Message, self).save(*args, **kwargs)

    class Meta:
        indexes = [
            models.Index(fields=["conversation", "timestamp"]),
            models.Index(fields=["conversation", "sender", "timestamp"]),
        ]

class UserConversationStatus(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE)
    unread_count = models.IntegerField(default=0)
    last_read_at = models.DateTimeField(default=0, null=True, blank=True)
    last_read_message_id = models.BigIntegerField(default=0, null=True, blank=True)

    class Meta:
        unique_together = ('user', 'conversation')

class Invitation(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    )
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='join_requests')
    invitee = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='invited_to_group')
    inviter = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_group_invites')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('group', 'invitee')

# 群公告模型
class GroupAnnouncement(models.Model):
    group = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='announcements')
    creator = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    content = models.TextField()
    create_time = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return self.content

    class Meta:
        indexes = [
            models.Index(fields=["group", "create_time"]),
        ]
        ordering = ["-create_time"]