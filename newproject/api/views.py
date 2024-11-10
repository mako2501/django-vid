from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializer import NoteSerializer
from .models import Note
from django.http import JsonResponse
#jwt
from datetime import datetime, timedelta
import jwt

#f. view jako arg. otrzymuje request a zwraca response
@api_view(['POST'])
def create_note(request):
    if not hasattr(request, 'user_id'):
        return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # kopia by moc nadpisac `user_id`
    data = request.data.copy()
    data['user_id'] = request.user_id

    serializer = NoteSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def note_detail(request, pk):
    try:
        note = Note.objects.get(pk=pk)
    except Note.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    # czy użytkownik jest właścicielem notatki
    if note.user_id != request.user_id:
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.method == 'GET':
        # zwroc wszystkie dane notatki
        serializer = NoteSerializer(note)
        return Response(serializer.data)

    elif request.method == 'PUT':
        #przygotowanie danych do aktualizacji
        data = request.data.copy()
        #dodanie user id przed zapisaniem - serializer wymaga tego pola a ja go nie rpzysylam
        data['user_id'] = note.user_id

        # aktualizacja danych notatki
        serializer = NoteSerializer(note, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)  # po aktualizacji zwraca dane
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        # usuwa notatke
        note.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

def notes_list(request):
    if not hasattr(request, 'user_id'):
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    notes = Note.objects.all().values('title', 'content','user_id')
    #notes = Note.objects.filter(user_id=request.user_id).values('title', 'content','user_id') #tylko tego usera
    return JsonResponse(list(notes), safe=False)
    

#widok do tworzenia tokena jwt symuloujacego logowanie - zwraca id usera
#csrf_exempt - jednak nie potrzeba
def simulate_login(request):
    # jakis id
    user_id = 2

    # tworzenie payload tokenuJWT
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=60),  # czas waznosci
        "iat": datetime.utcnow()
    }

    # generowanie tokneu JWT
    token = jwt.encode(payload, "tajny_kod_dzilimy_go_z_api_Spring", algorithm="HS256")

    return JsonResponse({"access_token": token})