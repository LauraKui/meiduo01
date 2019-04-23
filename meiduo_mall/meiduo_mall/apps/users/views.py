from django.shortcuts import render, redirect
from django.views.generic import View
from django.http import HttpResponseForbidden
from django.contrib.auth import login
import re
from .models import User
from django.db import DatabaseError
import logging
# Create your views here.
logger = logging.getLogger('django')


class Register(View):
    def get(self, request):
        return render(request, "register.html")

    
    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')    
        sms_code = request.POST.get('sms_code')
        allow = request.POST.get('allow')
        if not all([username, password, password2, mobile, sms_code, allow]):
            return HttpResponseForbidden('输入不能为空')

        if not re.match(r'^[a-zA-Z0-9_-]{5, 20}$', username): 
            return HttpResponseForbidden('请输入5-20的字符串')

        if not re.match(r'^[a-zA-Z0-9]{8, 20}$', psaaword):
            return HttpResponseForbidden('请输入8-20位的密码')

        if password2 != password:
            return HttpResponseForbidden('两次密码不相同')

        if not re.match(r'^1[3456789]\d{9}$', mobile):
            return HttpResponseForbidden('请输入有效手机号')
        try:
            user = User.objects.create_user(
                    
                    username = username,
                    mobile = mobile, 
                    password = password
                   
                    )
        except DatabaseError as e:
            
            logger.error(e)
            return render(request, 'register.html', {'register_errmsg': '用户注册失败'})

        login(request, user)
        return redirect('/')

