from __future__ import unicode_literals


# Create your models here.
from django.db import models
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
import random
import string

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


class User(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField()
    picture = models.ImageField()
    password_hash = models.CharField(max_length=30)
    logged = models.BooleanField(default=False)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        self.logged = True
        self.save()
        return s.dumps({'id': self.id})

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            print "SignatureExpired"
            return None
        except BadSignature:
            # Invalid Token
            print "BadSignature"
            return None
        user_id = data['id']
        print user_id
        user = User.objects.get(id=user_id)
        if user:
            if user.logged:
                return user_id
            else:
                return None
        return None

    @staticmethod
    def invalidate(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        user = User.objects.filter_by(id=user_id).first()
        if user:
            user.logged = False
            user.save()
            return user_id
        return None


class Request(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    meal_type = models.CharField(max_length=200)
    location_string = models.CharField(max_length=200)
    latitude = models.FloatField()
    longitude = models.FloatField()
    meal_time = models.DateTimeField()
    filled = models.BooleanField(default=False)


class Proposal(models.Model):
    user_proposed_to = models.CharField(max_length=200)
    user_proposed_from = models.CharField(max_length=200)
    request_id = models.ForeignKey(Request, on_delete=models.CASCADE)
    filled = models.BooleanField(max_length=200, default=False)


class MealDate(models.Model):
    user_1 = models.CharField(max_length=200)
    user_2 = models.CharField(max_length=200)
    restaurant_name = models.CharField(max_length=200)
    restaurant_address = models.CharField(max_length=200)
    restaurant_picture = models.CharField(max_length=200)
    meal_time = models.DateTimeField()

