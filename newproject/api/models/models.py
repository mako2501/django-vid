#from django.db import models

# stary model z .api - można usunąć
#teraz modele sa w w module models

'''
class Note(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True) # automatyczna aktualizacja czasu na puta
    user_id = models.IntegerField()

    def __str__(self):
        return self.title
'''