from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from pangea_django import PangeaAuthentication, generate_state_param

# Create your views here.

def landing(request):
    if request.user.is_authenticated:
        return redirect("/home")

    return redirect(f"https://pdn-dhkrualgjlcc43hh3mrvwggh3gjuxn6e.login.dev.aws.pangea.cloud?state={generate_state_param(request)}")

def post_login(request):
    user = PangeaAuthentication().authenticate(request=request)
    if user:
        return redirect("/home")
    return redirect("/")

@login_required(login_url="/")
def logout(request):
    user = PangeaAuthentication().logout(request)
    return redirect("/")

@login_required(login_url="/")
def home(request):
    context = {}
    context["user"] = request.user
    return render(request, "home.html", context)
