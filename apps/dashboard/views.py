from django.shortcuts import render, HttpResponse, redirect
import bcrypt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib import messages
from .models import *

# Create your views here.
def index(request):
	return render(request, 'dashboard/index.html')

def signin(request):
	return render(request, 'dashboard/signin.html')

def register(request):
	return render(request, 'dashboard/register.html')

def new(request):
	return render(request, 'dashboard/new_user.html')

def dashboard(request):

	if request.session.get('id') == None:
		redirect('/signin')


	user = User.objects.get(id=request.session['id'])
	request.session['first_name'] = user.first_name
	users = User.objects.all()
	context = {'user': user, 'users': users}
	return render(request, 'dashboard/dashboard.html', context)

def create_user(request):
	

	errors = User.objects.validate_user(request.POST)

	if len(errors):
		for tag, error in errors.iteritems():
			messages.error(request, error)
		if request.POST['form'] == "register":
			return redirect('/register')
		elif request.POST['form'] == "new_user":
			return redirect('/users/new')
	else:
		email = request.POST['email']
		first_name = request.POST['first_name']
		last_name = request.POST['last_name']
		password = request.POST['password']
		hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

		u = User.objects.all()
		if len(u) < 1:
			user_level = 9
		else:
			user_level = 1

		d = Description.objects.create(description="None")
		User.objects.create(first_name=first_name, last_name=last_name, email=email, password=hashed_pw, user_level=user_level ,description=d)
		
		if request.POST['form'] == "register":
			u = User.objects.get(email=email)
			request.session['id'] = u.id

		return redirect('/dashboard')

	return redirect('/')

def signin_user(request):

	email = request.POST['email']
	password = request.POST['password']

	# check if the user exists
	user = User.objects.filter(email=email)
	if len(user) > 0:
		# if it does, check password
		isPassword = bcrypt.checkpw(password.encode(), user[0].password.encode())
		if isPassword:
			request.session['id'] = user[0].id
			return redirect('/dashboard')
		else:
			# wrong password
			messages.error(request, "Incorrect username/password combination.")
			return redirect('/signin')
	else:
		# user doesn't exists
		messages.error(request, "User does not exists")
		return redirect('/signin')

def edit(request, id):
	user = User.objects.get(id=id)
	context = {'user': user}
	return render(request, 'dashboard/edit_user.html', context)

def edit_self(request):
	user = User.objects.get(id=request.session['id'])
	context = {'user': user}
	return render(request, 'dashboard/edit_user.html', context)

def update(request, id):

	if request.POST['form'] == "edit_information":
		errors = User.objects.validate_update_information(request.POST)
		if len(errors):
			for tag, error in errors.iteritems():
				messages.error(request, error)
			return redirect('/users/edit/{}'.format(id))
		else: 
			email = request.POST['email']
			first_name = request.POST['first_name']
			last_name = request.POST['last_name']
			if 'user_level' in request.POST:
				user_level = request.POST['user_level']
			else: 
				user_level = 1

			user = User.objects.get(id=id)
			user.first_name = first_name
			user.last_name = last_name
			user.email = email
			if user.id == request.session['id']:
				if user_level != User.objects.get(id=request.session['id']).user_level:
					messages.error(request, "You cannot change your own user level")
					user_level = User.objects.get(id=request.session['id']).user_level
					return redirect('/users/edit/{}'.format(id))
			user.user_level = user_level
			user.save()

			messages.success(request, "User successfully Updated")

			return redirect('/users/edit/{}'.format(id))

	elif request.POST['form'] == "update_password":
		errors = User.objects.validate_update_password(request.POST)
		if len(errors):
			for tag, error in errors.iteritems():
				messages.error(request, error)
			return redirect('/users/edit/{}'.format(id))
		else:
			password = request.POST['password']
			hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

			user = User.objects.get(id=id)
			user.password = hashed_pw
			user.save()

			messages.success(request, "Password successfully Updated")

			return redirect('/users/edit/{}'.format(id))
	elif request.POST['form'] == "update_description":
		description = request.POST['description']
		user = User.objects.get(id=id)
		user.description.description = description
		user.description.save()

		messages.success(request, "Description successfully Updated")

		return redirect('/users/edit/{}'.format(id))


	return redirect('/users/edit/{}'.format(id))


def show(request, id):
	user = User.objects.get(id=id)
	context = {'user': user}
	return render(request, 'dashboard/show_user.html', context)

def logout(request):
	request.session.clear()
	return redirect('/signin')

def destroy(request, id):
	print request.session['id']
	user = User.objects.get(id=id)
	context = {'user': user}
	return render(request, 'dashboard/confirm_destroy.html', context)

def delete(request, id):
	user = User.objects.get(id=id)
	user.delete()
	return redirect('/dashboard')





