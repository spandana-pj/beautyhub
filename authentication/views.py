from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from django.conf import settings
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout

# Create your views here.

def signup(request):
    if request.method=="POST":
        email=request.POST['email']
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return render(request,'signup.html')
        try:
            if User.objects.get(username=email):
                messages.info(request,'Email is already taken')
                return render(request,'signup.html')
        except:
            pass   
        user = User.objects.create_user(email,email,password)
       # user.is_active=False
        user.save()
        email_subject="Activate Your Account"
        message=render_to_string('activate.html',{
            'user':user,
            'domain':'127.0.0.1:5000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)

        })

        #email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
        #email_message.send()  
        return redirect('/auth/login/')    

      
                    
    return render(request,"signup.html")


  


class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_text(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/auth/login')
        return render(request,'activatefail.html')



def handlelogin(request):
   
    if request.method=='POST':
        username=request.POST.get('email')
        password=request.POST.get('pass1')
        
        if not User.objects.filter(username=username).exists():
            messages.error(request,'Invalid user')
            return redirect('/auth/login/')

        user=authenticate(username=username,password=password)

        if user is None:
            messages.error(request,'Invalid Password')
            return redirect('/auth/login/')
        else:
            login(request,user)
            messages.info(request,'logged in successfully')
            return redirect('/')
    return render(request,'login.html')



def handlelogout(request):
    logout(request)
    messages.info(request,"Logout Success")
    return redirect('/auth/login')


