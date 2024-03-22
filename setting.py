#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
@ Project     : QtLoginRegistrationClient
@ File        : setting.py
@ Author      : yqbao
@ Version     : V1.0.0
@ Description : 
"""
import os


# 使用方法：若需要修改默认参数，则直接在子类中用相同参数名称重新设置即可
class Setting(object):
    BASE_PATH = os.path.dirname(__file__)  # Setting.py 所在的绝对路径
    BASE_DIR = os.path.abspath(BASE_PATH)
    ENV = "PROD"
    API_HOST = 'http://192.167.6.139:8000'
    DEBUG = False

    def __getitem__(self, key):
        return self.__getattribute__(key)


class DevelopConfig(Setting):
    """本地开发环境"""
    ENV = "DEV"
    API_HOST = 'http://192.167.6.139:8000'
    DEBUG = True


# 环境映射关系
mapping = {
    'develop': DevelopConfig,
}

CONFIG = mapping[os.environ.get('APP_ENV', 'develop').lower()]()  # 开发
