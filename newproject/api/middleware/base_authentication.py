from abc import ABC, abstractmethod
from django.http import JsonResponse

#klasa abstrakcyjna dla middleware
class BaseAuthenticationMiddleware(ABC):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # spr. czy request ma byc przetwrzany
        if self.should_skip(request):
            return self.get_response(request)

        #pobierz token z requestu
        token = self.get_token_from_request(request)
        if not token:
            return JsonResponse({'error': 'Token not provided'}, status=401)
        
        # weryfikacja tokenu
        verified_token = self.forward_token_to_api(token)
        if not verified_token:
            return JsonResponse({'error': 'Token is not valid in API'}, status=401)

        # odszyfruj token, zwraca jakies dane usera
        user_data = self.decode_token(verified_token)
        if not user_data:
            return JsonResponse({'error': 'Token decoding failed'}, status=401)

        #dodaj dane usera do requesta
        request.user_data = user_data

        # kontynuacja przetwarzania - w request znajduje się user_id
        return self.get_response(request)

    @abstractmethod
    def should_skip(self, request):
        """spr. czy middleware ma przetwarzać request, zwraca T/F"""
        pass

    @abstractmethod
    def get_token_from_request(self, request):
        """pobiera token z requestu, zwraca token"""
        pass

    @abstractmethod
    def forward_token_to_api(self, token):
        """wwysyla token do api w celu jego spradzenia, zwraca token"""
        pass

    @abstractmethod
    def decode_token(self, token):
        """dekoduje token, ma zwracac odkodowany payload"""
        pass
