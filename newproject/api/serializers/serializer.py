'''
#stary serializer, wyciagniety z .api, mozna usunac

from rest_framework import serializers
from .models.note import Note

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['id', 'title', 'content', 'created_at', 'updated_at', 'user_id']
'''