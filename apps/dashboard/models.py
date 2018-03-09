from __future__ import unicode_literals

from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from django.db import models

# Create your models here.

class Description(models.Model):
	description = models.TextField()


class UserManager(models.Manager):
	def validate_user(request, postData):
		errors = {}


		# validate first name
		if len(postData['first_name']) < 2 or not postData['first_name'].isalpha():
			if len(postData['first_name']) < 2:
				errors['first_name_length'] = "First Name must be at least two characters."
			if not postData['first_name'].isalpha():
				errors['first_name_alpha'] = "First Name can only contain letters."

		# validate last name
		if len(postData['last_name']) < 2 or not postData['last_name'].isalpha():
			if len(postData['last_name']) < 2:
				errors['last_name_length'] = "Last Name must be at least two characters."
			if not postData['first_name'].isalpha():
				errors['lst_name_alpha'] = "Last Name can only contain letters."

		# validate email
		try:
			validate_email(postData['email'])
		except ValidationError:
			errors['email'] = "This is not a valid email."
		else:

			if User.objects.filter(email=postData['email']):
				errors['email'] = "This user already exists."


		# validate email
		if len(postData['password']) < 8 and postData['password'].isalpha():
			if len(postData['password']) < 8:
				errors['password_length'] = "Password must be at least 8 characters."
			if postData['password'].isalpha():
				errors['password_alpha'] = "Password must contain one number or special character."

		# check if passwords match
		if postData['password'] != postData['confirm_pw']:
			errors['confirm_pw'] = "Passwords must match"


		return errors


class User(models.Model):
	email = models.CharField(max_length=255)
	first_name = models.CharField(max_length=50)
	last_name = models.CharField(max_length=50)
	password = models.CharField(max_length=255)
	user_level = models.IntegerField(default=1)
	description = models.OneToOneField(Description)
	created_at = models.DateTimeField(auto_now_add = True)
	updated_at = models.DateTimeField(auto_now = True)

	objects = UserManager()

class MessageManager(models.Manager):
	def validate_message(request, postData):
		errors = {}

		return errors

class Message(models.Model):
	author = models.ForeignKey(User, related_name="posts")
	message = models.TextField()
	for_user = models.ForeignKey(User, related_name="messages")


