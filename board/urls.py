from django.urls import path, include
import board.views as views
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/get_user_info/<int:id>', views.get_user_info),
    path('user/register', views.register),
    path('user/logoff', views.logoff),
    path('user/login', views.login),
    path('user/update_normal_info', views.update_normal_info),
    path('user/update_auth_info', views.update_auth_info),
    path('user/search_friends', views.search_friends),
    path('user/profile/<str:username>', views.get_user_profile),
    path('user/send_friend_request', views.send_friend_request),
    path('user/friend_requests', views.get_friend_requests),
    path('user/respond_friend_request', views.respond_friend_request),
    path('user/delete_friend', views.delete_friend),
    path('user/get_friends', views.get_friends),
    path('user/add_friend_to_friend_group', views.add_friend_to_friend_group),
    
    path('user/get_private_conversations', views.get_private_conversations),
    path('user/conversation/<int:conversation_id>', views.conversation),
    path('user/send_message', views.send_message),
    path('user/delete_message', views.delete_message),
    path('user/records/<int:conversation_id>', views.records),
    path('user/delete_records/<int:conversation_id>', views.delete_records),
    path('user/reply_message', views.reply_message),

    path('user/create_group_conversation', views.create_group_conversation),
    path('user/get_group_conversations', views.get_group_conversations),
    path('user/add_admin', views.add_admin),
    path('user/remove_admin', views.remove_admin),
    path('user/transfer_owner', views.transfer_owner),
    path('user/remove_member', views.remove_member),
    path('user/invite_member', views.invite_member),
    path('user/review_invitation', views.review_invitation),
    path('user/view_invitations/<int:group_id>', views.view_invitations),
    path('user/respond_invitation', views.review_invitation),
    path('user/quit_group', views.quit_group),
    path('user/delete_group', views.delete_group),
    path('user/create_group_announcement', views.create_group_announcement),
    path('user/get_group_announcements/<int:group_id>', views.get_group_announcements),
]
