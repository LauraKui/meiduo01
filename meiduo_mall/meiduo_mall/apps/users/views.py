from django.shortcuts import render, redirect
from django.views.generic import View
from django.http import HttpResponseForbidden, JsonResponse
from django.contrib.auth import login, authenticate
import re
from .models import User
from django.db import DatabaseError
from django_redis import get_redis_connection
import logging
from django.urls import reverse
from meiduo_mall.utils.response_code import RETCODE
# Create your views here.

# 创建日志输出器对象
logger = logging.getLogger('django')


class Register(View):
    def get(self, request):
        return render(request, "register.html")

    
    def post(self, request):
        # 接收由表单发送过来的数据， 用post接收，以下6个元素是必须传的
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')    
        sms_code = request.POST.get('sms_code')
        allow = request.POST.get('allow')
        # 进行验证
        # all()用来验证传入的数据是否齐全，只要是none, False, '', 都表示不全
        #  allow如果勾选是'on'，否则是'None' 
        if not all([username, password, password2, mobile, sms_code, allow]):
            return HttpResponseForbidden('输入不能为空')
        # 判断用户名是否符合标准
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username): 
            return HttpResponseForbidden('请输入5-20的字符串')
        # 判断密码
        if not re.match(r'^[a-zA-Z0-9]{8,20}$', password):
            return HttpResponseForbidden('请输入8-20位的密码')

        if password2 != password:
            return HttpResponseForbidden('两次密码不相同')
        # 判断手机号
        if not re.match(r'^1[3456789]\d{9}$', mobile):
            return HttpResponseForbidden('请输入有效手机号')
        # 判断短信验证码
        redis_conn = get_redis_connection('verify_code')
        sms_code_server = redis_conn.get('sms: %s' % mobile)
        if sms_code_server is None or sms_code != sms_code_server.decode():
            return HttpResponseForbidden('短信验证码输入不正确')


        try:
            # 创建用户，使用User模型类里面的create_user()方法创建，里面封装了set_password()方法加密密码
            user = User.objects.create_user(
                    # 只有此三项需要永久保存在数据库中的
                    username = username,
                    mobile = mobile, 
                    password = password
                   
                    )
            # 定义一个e对象来接收错误信息的内容
        except DatabaseError as e:
            # 把错误信息保存在日志中
            logger.error(e)
            return render(request, 'register.html', {'register_errmsg': '用户注册失败'})
        # 状态保持
        # 储存用户的id到session中记录它的登陆状态
        login(request, user)
        # 登陆成功重定向到首页
        return redirect(reverse("contents:index"))


class CheckUserView(View):
    def get(self, request, username):

        count = User.objects.filter(username=username).count()
        return JsonResponse({'count': count, 'code': RETCODE.OK, 'errmsg': 'OK'})


class CheckMobileView(View):
    def get(self, request, mobile):
        count = User.objects.filter(mobile=mobile).count()
        return JsonResponse({'count': count, 'code': RETCODE.OK, 'errmsg': 'OK'})


class LoginView(View):
    def get(self, request):
        return render(request, "login.html")

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        if not all([username, password]):
            return HttpResponseForbidden("缺少传入参数")
        user = authenticate(username=username, password=password)
        if user is None:
            return render(request, 'login.html', {'account_errmsg': '用户名或密码错误'})

        login(request, user)

        if remembered != 'on':
            request.session.set_expiry(0)

        return redirect(reverse("contents:index"))


