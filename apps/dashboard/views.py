from django.shortcuts import render

# Create your views here.
def index(request):
	return render(request, 'dashboard/index.html')

def signin(request):
	return render(request, 'dashboard/signin.html')

def register(request):
	return render(request, 'dashboard/register.html')