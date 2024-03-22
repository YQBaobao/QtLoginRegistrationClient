#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
@ Project     : QtLoginRegistrationClient
@ File        : network.py
@ Author      : yqbao
@ Version     : V1.0.0
@ Description : 
"""
import json
from typing import Union

from PyQt5 import QtCore, QtNetwork
from PyQt5.QtCore import QObject, QByteArray, QJsonDocument

from lib.basic_function import BasicFunction


class Network(QObject):

    def __init__(self, basic_function: BasicFunction, parent=None):
        super().__init__(parent=parent)
        self.basic_function = basic_function

    def get(self, url: str, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """get"""
        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))

        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.manager.get(self.http)
        return self.manager

    def post_x_www(self, url: str, data: str, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """post application/x-www-form-urlencoded"""
        repost_body = QByteArray()
        repost_body.append(data)
        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))

        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.http.setHeader(QtNetwork.QNetworkRequest.ContentTypeHeader, "application/x-www-form-urlencoded")
        self.manager.post(self.http, repost_body)
        return self.manager

    def post_json(self, url: str, body: dict, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """post application/json"""
        data = QtCore.QByteArray()
        document = QJsonDocument(body)
        data.append(document.toJson(QJsonDocument.Compact))

        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))
        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.http.setHeader(QtNetwork.QNetworkRequest.ContentTypeHeader, "application/json")
        self.manager.post(self.http, data)
        return self.manager

    def put_x_www(self, url: str, data: str, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """put application/x-www-form-urlencoded"""
        repost_body = QByteArray()
        repost_body.append(data)
        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))

        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.http.setHeader(QtNetwork.QNetworkRequest.ContentTypeHeader, "application/x-www-form-urlencoded")
        self.manager.put(self.http, repost_body)
        return self.manager

    def put_json(self, url: str, body: dict, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """put application/json"""
        data = QtCore.QByteArray()
        document = QJsonDocument(body)
        data.append(document.toJson(QJsonDocument.Compact))

        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))
        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.http.setHeader(QtNetwork.QNetworkRequest.ContentTypeHeader, "application/json")
        self.manager.put(self.http, data)
        return self.manager

    def delete(self, url: str, authorization: str = None) -> QtNetwork.QNetworkAccessManager:
        """delete"""
        self.http = QtNetwork.QNetworkRequest(QtCore.QUrl(url))

        self.manager = QtNetwork.QNetworkAccessManager()
        if authorization:
            auth = bytes("Bearer " + authorization, encoding="utf-8")
            self.http.setRawHeader(bytes("Authorization", encoding="utf-8"), auth)
        self.manager.deleteResource(self.http)
        return self.manager

    def response(self, manager: QtNetwork.QNetworkAccessManager, reply: QtNetwork.QNetworkReply):
        er = reply.error()
        bytes_string: Union[QByteArray, bytes] = reply.readAll()
        string = str(bytes_string, 'utf-8')
        response = json.loads(string)
        manager.deleteLater()
        if er != QtNetwork.QNetworkReply.NetworkError.NoError:
            try:
                self.basic_function.info_message(response['detail'])
                return
            except TypeError:
                print(response)
        return response
