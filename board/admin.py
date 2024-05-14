from django.contrib import admin
from .models import CustomUser, FriendGroup, Friendship, FriendshipRequest, Conversation

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(FriendGroup)
admin.site.register(Friendship)
admin.site.register(FriendshipRequest)
admin.site.register(Conversation)