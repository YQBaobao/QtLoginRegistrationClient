#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
@ Project     : QtLoginRegistrationClient
@ File        : login_register.py
@ Author      : yqbao
@ Version     : V1.0.0
@ Description :
"""
from hashlib import md5

from PyQt5 import QtNetwork
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QDialog
from email_validator import validate_email, EmailNotValidError

from lib import crypto
from lib.basic_function import BasicFunction
from lib.network import Network
from uis.LoginRegisterEmail import Ui_LoginRegister
from setting import CONFIG

API_HOST = CONFIG.API_HOST


class UiLoginRegisterQDialog(QDialog, Ui_LoginRegister):
    """界面逻辑"""
    url_token = f'{API_HOST}/token'
    url_send_email = f'{API_HOST}/user/login-signup/send-email'
    url_register = f'{API_HOST}/user/login-signup/sign-up'
    url_forget_password = f'{API_HOST}/user/login-signup/update-password'

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setupUi(self)

        self.init_ui()
        self.basic_function = BasicFunction(self)
        self.network = Network(basic_function=self.basic_function)

    def init_ui(self):
        """初始化"""
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, on=False)  # 去掉 QDialog 帮助问号
        self.stackedWidget.setCurrentIndex(0)  # 默认登录页
        self.pushButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(0))  # 切换登录页
        self.pushButton_2.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))  # 切换注册页
        self.pushButtonForget.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(2))  # 切换忘记密码页
        self.init_time()

        # 登录页需要绑定的信号
        self.pushButtonLogin.clicked.connect(self.login)

        # 注册页需要绑定的信号
        self.pushButtonSend.clicked.connect(self.register_send_active_email)
        self.lineEdit_3.textEdited.connect(
            lambda: self.check_password(self.lineEdit_3, self.lineEdit_4, self.label_9, self.pushButtonRegister))
        self.lineEdit_4.textEdited.connect(
            lambda: self.check_password(self.lineEdit_3, self.lineEdit_4, self.label_9, self.pushButtonRegister))
        self.pushButtonRegister.clicked.connect(self.register)

        # 忘记密码页绑定信号
        self.pushButtonSend2.clicked.connect(self.forget_password_send_active_email)
        self.lineEdit_7.textEdited.connect(
            lambda: self.check_password(self.lineEdit_7, self.lineEdit_8, self.label_14, self.pushButtonForgetOk))
        self.lineEdit_8.textEdited.connect(
            lambda: self.check_password(self.lineEdit_7, self.lineEdit_8, self.label_14, self.pushButtonForgetOk))
        self.pushButtonForgetOk.clicked.connect(self.forget_password)

        # 窗口切换信号
        self.stackedWidget.currentChanged.connect(self.update_stacked_widget)

        # 记住
        self.accounts = 'remember'
        crypto.create_db(self.accounts)  # 创建存储库
        self.init_remember()

    def init_time(self):
        self.count = 60
        self.time = QTimer(self)
        self.time.setInterval(1000)

    def init_remember(self):
        """初始化"""
        if not self.required_remember():
            return
        self.lineEditUsername.setText(self.username)
        self.lineEditPassword.setText(self.password)
        return True

    def update_stacked_widget(self):
        self.lineEditUsername.clear()
        self.lineEditPassword.clear()
        self.lineEdit.clear()
        self.lineEdit_2.clear()
        self.lineEdit_3.clear()
        self.lineEdit_4.clear()
        self.lineEdit_5.clear()
        self.lineEdit_6.clear()
        self.lineEdit_7.clear()
        self.lineEdit_8.clear()
        self.lineEdit_9.clear()

    def login(self):
        """登录动作"""
        if not self.required_login():  # 必填校验未通过
            return
        if not self.check_email_format(self.lineEditUsername):
            return
        bytes_my_password = bytes(self.password, encoding="utf-8")
        md5_my_password = md5(bytes_my_password).hexdigest()
        body = f"grant_type=&username={self.username}&password={md5_my_password}&scope=&client_id=&client_secret="
        self.manager = self.network.post_x_www(self.url_token, body)
        self.manager.finished.connect(self.login_response)

    def login_response(self, reply: QtNetwork.QNetworkReply):
        response = self.network.response(self.manager, reply)
        if not response:
            return
        self.access_token = response['access_token']
        self.accept()
        self.update_login_config(self.password)

    def update_login_config(self, password):
        """手动登录更新配置文件"""
        if not self.checkBox.isChecked():
            crypto.delete_db(self.accounts)
            return
        crypto.delete_db(self.accounts)
        crypto.insert_db(self.accounts, self.username, password)

    def register(self):
        """注册动作"""
        if not self.required_register():  # 必填校验未通过
            return
        if not self.check_email_format(self.lineEdit_2):
            return
        bytes_my_password = bytes(self.password, encoding="utf-8")
        md5_my_password = md5(bytes_my_password).hexdigest()
        body = {
            "username": self.username,
            "password": md5_my_password,
            "email": self.email,
            "captcha": self.captcha
        }
        self.manager = self.network.post_json(self.url_register, body)
        self.manager.finished.connect(self.register_response)

    def register_response(self, reply: QtNetwork.QNetworkReply):
        response = self.network.response(self.manager, reply)
        if not response:
            return
        # 注册成功后，判断是否选中直接登录,若未选中，则切换会登录页
        if self.checkBox_2.isChecked():
            bytes_my_password = bytes(self.password, encoding="utf-8")
            md5_my_password = md5(bytes_my_password).hexdigest()
            body = f"username={self.username}&password={md5_my_password}"
            self.manager = self.network.post_x_www(self.url_token, body)
            self.manager.finished.connect(self.login_response)
        else:
            self.stackedWidget.setCurrentIndex(0)

    def register_send_active_email(self):
        """发送验证码"""
        if not self.required_send_email(self.lineEdit_2):  # 必填校验未通过
            return
        if not self.check_email_format(self.lineEdit_2):
            return
        self.time.timeout.connect(lambda: self.refresh_time(self.pushButtonSend))
        if self.pushButtonSend.isEnabled():
            self.time.start()
            self.pushButtonSend.setEnabled(False)
        # 发送邮件
        self.manager = self.network.post_json(self.url_send_email, {"email": self.email})
        self.manager.finished.connect(self.send_email_response)

    def send_email_response(self, reply: QtNetwork.QNetworkReply):
        response = self.network.response(self.manager, reply)
        if not response:
            return
        result = self.check_send_email_result(response)
        if result is not True and result:
            self.basic_function.info_message(result)

    def check_email_format(self, email_line_edit):
        """邮箱格式校验"""
        email = email_line_edit.text()
        if email_line_edit.objectName() == "lineEditUsername":
            return True
        try:
            info = validate_email(email, check_deliverability=False)
            self.email = info.normalized
            return True
        except EmailNotValidError:
            self.basic_function.info_message("邮箱格式不正确，请重新输入")
            return

    @staticmethod
    def check_send_email_result(response):
        """检查邮箱发送结果"""
        try:
            status = response['data']['status']
            if status == 200:
                return True
            return response['data']['msg']
        except Exception:
            return

    def check_password(self, password_line_edit, old_password_line_edit, label, push_button):
        """重复密码的验证"""
        self.password = password_line_edit.text()
        self.repeat_password = old_password_line_edit.text()
        if self.password != self.repeat_password:
            label.setStyleSheet("color: rgb(255, 0, 0);")
            label.setText("两次密码输入不一致，重新输入")
            push_button.setEnabled(False)
            return
        label.setText("")
        push_button.setEnabled(True)

    def forget_password_send_active_email(self):
        """发送验证码"""
        if not self.required_send_email(self.lineEdit_6):  # 必填校验未通过
            return
        if not self.check_email_format(self.lineEdit_6):
            return
        self.time.timeout.connect(lambda: self.refresh_time(self.pushButtonSend2))
        if self.pushButtonSend2.isEnabled():
            self.time.start()
            self.pushButtonSend2.setEnabled(False)
        # 发送邮件
        self.manager = self.network.post_json(self.url_send_email, {"email": self.email})
        self.manager.finished.connect(self.send_email_response)

    def refresh_time(self, captcha_push_button):
        if self.count > 0:
            captcha_push_button.setText(str(self.count) + '秒后重发')
            self.count -= 1
        else:
            self.time.stop()
            captcha_push_button.setEnabled(True)
            captcha_push_button.setText('发送')
            self.count = 60

    def forget_password(self):
        """忘记密码动作"""
        if not self.required_forget_password():
            return
        if not self.check_email_format(self.lineEdit_6):
            return
        bytes_my_password = bytes(self.password, encoding="utf-8")
        md5_my_password = md5(bytes_my_password).hexdigest()
        body = {
            "password": md5_my_password,
            "email": self.email,
            "captcha": self.captcha
        }
        self.manager = self.network.post_json(self.url_forget_password, body)
        self.manager.finished.connect(self.register_response)
        # 注册成功后，判断是否选中找回密码后直接登录,若未选中，则切换会登录页
        if self.checkBox_3.isChecked():
            self.accept()
        else:
            self.stackedWidget.setCurrentIndex(0)

    def required_login(self):
        """登录必填校验"""
        self.username = self.lineEditUsername.text()
        self.password = self.lineEditPassword.text()
        if not self.username.strip():
            self.basic_function.info_message("用户账号不能为空")
            return False
        elif not self.password.strip():
            self.basic_function.info_message("用户密码不能为空")
            return False
        return True

    def required_register(self):
        """注册必填校验"""
        self.username = self.lineEdit.text()
        self.captcha = self.lineEdit_5.text()
        self.email = self.lineEdit_2.text()
        self.password = self.lineEdit_3.text()
        if not self.username.strip():
            self.basic_function.info_message("账号不能为空")
            return False
        elif not self.email.strip():
            self.basic_function.info_message("邮箱地址不能为空")
            return False
        elif not self.password.strip():
            self.basic_function.info_message("用户密码不能为空")
            return False
        elif not self.repeat_password.strip():
            self.basic_function.info_message("重复密码不能为空")
            return False
        elif not self.captcha.strip():
            self.basic_function.info_message("邮箱验证码不能为空")
            return False
        return True

    def required_forget_password(self):
        self.email = self.lineEdit_6.text()
        self.password = self.lineEdit_7.text()
        self.captcha = self.lineEdit_9.text()
        if not self.email.strip():
            self.basic_function.info_message("邮箱地址不能为空")
            return False
        elif not self.password.strip():
            self.basic_function.info_message("用户密码不能为空")
            return False
        elif not self.repeat_password.strip():
            self.basic_function.info_message("重复密码不能为空")
            return False
        elif not self.captcha.strip():
            self.basic_function.info_message("邮箱验证码不能为空")
            return False
        return True

    def required_send_email(self, email_line_edit):
        self.email = email_line_edit.text()
        if not self.email.strip():
            self.basic_function.info_message("邮箱地址不能为空")
            return False
        return True

    def required_remember(self):
        """自动登录参数校验"""
        try:
            self.username, self.password = crypto.decrypt(self.accounts)
            if not self.username.strip() or not self.password.strip():
                return False
        except IndexError:
            return False
        return True

    def closeEvent(self, event) -> None:
        super(UiLoginRegisterQDialog, self).closeEvent(event)
        self.reject()
