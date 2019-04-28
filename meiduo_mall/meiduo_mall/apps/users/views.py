from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.generic import View
from django.http import HttpResponseForbidden, JsonResponse
from django.contrib.auth import login, authenticate, logout, mixins
from django_redis import get_redis_connection
from django.db import DatabaseError
from django.core.mail import send_mail

import re
import logging
import json

from django.conf import settings
from .models import User
from meiduo_mall.utils.response_code import RETCODE
from celery_tasks.email.tasks import send_verify_mail
from .utils import get_verify_url, check_token
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
        # return redirect(reverse("contents:index"))
        response = redirect(request.GET.get('next', '/'))
        # 前端通过获取cookie值来取得username, 因此要设置cookie值
        response.set_cookie('username', user.username, max_age=settings.SESSION_COOKIE_AGE)
        return response


class CheckUserView(View):
    def get(self, request, username):

        count = User.objects.filter(username=username).count()
        return JsonResponse({'count': count, 'code': RETCODE.OK, 'errmsg': 'OK'})


class CheckMobileView(View):
    def get(self, request, mobile):
        count = User.objects.filter(mobile=mobile).count()
        return JsonResponse({'count': count, 'code': RETCODE.OK, 'errmsg': 'OK'})


class LoginView(View):
    """用户登录"""
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

        response = redirect(request.GET.get('next', '/'))
        # 前端通过获取cookie值来取得username, 因此要设置cookie值
        response.set_cookie('username', user.username, max_age=settings.SESSION_COOKIE_AGE)
        return response


class LogoutView(View):
    """推出登录"""
    def get(self, request):

        logout(request)
        response = redirect(reverse("users:login"))
        response.delete_cookie('username')
        return response

class UserInfo(mixins.LoginRequiredMixin, View):
    def get(self, request):
        # 方法1：
        # user = request.user
        # 登录了直接到用户中心
        # if user.is_authenticated:
        #     return render(request, 'user_center_info.html')
        # 如果没有登录， 则跳转到登录页面， 且登录后再自动跳转到用户中心
        # else:
        #     return redirect('/login/?next=/info/')
        # 方法2：
        return render(request, 'user_center_info.html')

class EmailView(mixins.LoginRequiredMixin, View):
    def put(self,request):
        data = json.loads(request.body.decode())
        email = data.get('email')
        if not all([email]):
            return HttpResponseForbidden("缺少邮箱数据")
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return HttpResponseForbidden("邮箱格式有误")
        user = request.user
        user.email = email
        user.save()
        # 在此地需要进行邮件发送，异步
        verify_url = get_verify_url(user)
        send_verify_mail.delay(email, verify_url)
        # to_email = email
        # subject = "美多商城邮箱验证"
        # html_message = '<p>尊敬的用户您好！</p>' \
        #                '<p>感谢您使用美多商城。</p>' \
        #                '<p>您的邮箱为：%s 。请点击此链接激活您的邮箱：</p>' \
        #                '<p><a href="%s">%s<a></p>' % (to_email, verify_url, verify_url)
        # send_mail(subject, '', settings.EMAIL_FROM, [to_email], html_message=html_message)

        return JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})


class VerifyEmailView(View):
    def get(self, request):
        token = request.GET.get('token')
        user = check_token(token)
        if user is None:
            return HttpResponseForbidden('token无效')

        # 修改当前user.email_active=True
        user.email_active = True
        user.save()

        # 响应
        return redirect('/info/')