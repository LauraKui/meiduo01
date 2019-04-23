from django.shortcuts import render
from django.views.generic import View
# Create your views here.
from meiduo_mall.libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from django.http import HttpResponse


class ImageCodeView(View):
    def get(self, request, uuid):
        name, text, image = captcha.generate_captcha()
        redis_conn = get_redis_connection('verify_code')
        redis_conn.setex('img: %s' % uuid, 300, text)
        return HttpResponse(image, content_type='image/png')

