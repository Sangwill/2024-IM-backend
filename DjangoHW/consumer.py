import json
from channels.generic.websocket import AsyncWebsocketConsumer

class IMConsumer(AsyncWebsocketConsumer):
    # 当客户端尝试建立 WebSocket 连接时调用
    async def connect(self) -> None:
        # 从查询字符串中提取用户名
        self.username: str = self.scope['query_string'].decode('utf-8').split('=')[1]

        # 将当前 WebSocket 连接添加到一个全体用户组中
        # 这样可以确保发给这个组的所有消息都会被转发给目前连接的所有客户端
        await self.channel_layer.group_add(self.username, self.channel_name)

        # 接受 WebSocket 连接
        await self.accept()

    # 当 WebSocket 连接关闭时调用
    async def disconnect(self, close_code: int) -> None:
        # 将当前 WebSocket 从其所在的组中移除
        await self.channel_layer.group_discard(self.username, self.channel_name)

    # 向指定用户组发送 notification
    async def notify(self, event) -> None:
        conversation_id = event['conversation_id']
        sender_id = event['sender_id']
        sender_name = event['sender_name']
        sender_avatar = event['sender_avatar']
        message_id = event['message_id']
        content = event['content']
        timestamp = event['timestamp']
        unread_count = event['unread_count']
        last_read_map = event['last_read_map']
        reply_to = event["reply_to"]

        await self.send(text_data=json.dumps({
            'type': 'notify',
            'conversation_id': conversation_id,
            'sender_id': sender_id,
            'sender_name': sender_name,
            'sender_avatar': sender_avatar,
            'message_id': message_id,
            'content': content,
            'timestamp': timestamp,
            'unread_count': unread_count,
            'last_read_map': last_read_map,
            'reply_to': reply_to,
        }))

    async def read(self, event) -> None:
        conversation_id = event['conversation_id']
        unread_count = event['unread_count']
        last_read_map = event['last_read_map']

        await self.send(text_data=json.dumps({
            'type': 'read',
            'conversation_id': conversation_id,
            'unread_count': unread_count,
            'last_read_map': last_read_map,
        }))