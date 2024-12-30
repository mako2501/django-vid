"""
Author: 14798
Desc: Interfejs dla middleware pośredniczacego w komuniakcji miedzy frontem, a sererem Spring
"""

from abc import ABC, abstractmethod

class AuthenticationInterface(ABC):
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
        """wwysyla token do api w celu jego spradzenia, zwraca zaszyfrowany user_id"""
        pass

    @abstractmethod
    def decode_token(self, token):
        """odszyfruwuje user_id, ma zwracac user_id"""
        pass
