#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import sys
import json
import datetime
import logging
import hashlib
import uuid
from abc import ABC
from optparse import OptionParser
from weakref import WeakKeyDictionary
from http.server import HTTPServer, BaseHTTPRequestHandler

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


def configure_logger(logger_file_name):
    logger_config = {
        'filemode': 'w',
        'level': logging.INFO,
        'format': '[%(asctime)s] %(levelname).1s %(message)s',
        'datefmt': '%Y.%m.%d %H:%M:%S'
    }

    if logger_file_name:
        logger_config['filename'] = logger_file_name
    else:
        logger_config['stream'] = sys.stdout

    logging.basicConfig(**logger_config)


class ValidationError(ValueError):
    def __init__(self, text):
        self.text = text


class Field:
    field_type = None

    def __init__(self, required, nullable):
        self.required = required
        self.nullable = nullable
        self.field = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.field.get(instance)

    def __set__(self, instance, value):
        if value is None:
            if not self.required:
                self.field[instance] = None
                return
            else:
                raise ValidationError("Field '{0}' is required, but not provided")

        if not value:
            if self.nullable:
                self.field[instance] = self.field_type()
            else:
                raise ValidationError("Field '{0}' is not nullable")

        if not isinstance(value, self.field_type):
            raise ValidationError("Field '{0}' must be of " + str(self.field_type))

        if self.value_check(value):
            self.field[instance] = value

    def value_check(self, value):
        return True

    def valid(self, instance):
        return bool(self.field.get(instance))


class CharField(Field):
    field_type = str


class ArgumentsField(Field):
    field_type = dict


class EmailField(CharField):
    def value_check(self, value):
        if '@' not in value:
            raise ValidationError("Field '{0}' is not valid. '@' symbol not present in the analysed string")

        return True


class PhoneField(CharField):
    def __set__(self, instance, value):
        if value and isinstance(value, int):
            value = str(value)

        super().__set__(instance, value)

    def value_check(self, value):
        error_strings = []

        if not value.isdecimal():
            error_strings.append("Not a decimal value provided")

        if len(value) != 11:
            error_strings.append("Wrong phone number length")

        if not value.startswith('7'):
            error_strings.append("The phone number must begin with '7'")

        if error_strings:
            raise ValidationError("Field '{0}' is not valid. " + '; '.join(error_strings))

        return True


class DateField(Field):
    field_type = datetime.date

    def __set__(self, instance, value):
        if isinstance(value, str):
            try:
                value = datetime.datetime.strptime(value, "%d.%m.%Y").date()
            except ValueError as e:
                raise ValidationError("Field '{0}' is not valid. '" + value + "' is not a date of dd.mm.yyyy format")

        super().__set__(instance, value)


class BirthDayField(DateField):
    def value_check(self, value):
        delta = datetime.datetime.now().date() - value

        if delta.days / 365 > 70:
            raise ValidationError("Field '{0}' is not valid. The person's age is greater then 70 years")

        return True


class GenderField(Field):
    field_type = int

    def value_check(self, value):
        if 0 <= value <= 2:
            return True
        else:
            raise ValidationError("Field '{0}' is not valid. Gender id must be between 0 and 2")

    def valid(self, instance):
        return self.field.get(instance) is not None


class ClientIDsField(Field):
    field_type = list

    def __init__(self, required):
        super().__init__(required, False)

    def value_check(self, value):
        error_strings = [str(v) + " is not a valid integer" for v in value if not isinstance(v, int)]

        if error_strings:
            raise ValidationError("Field '{0}' is not valid." + '; '.join(error_strings))

        return True


class Request:
    def __init__(self, arguments):
        if arguments:
            error_strings = []
            field_names = [k for k, v in self.generate_dict_field_items()]

            for f in field_names:
                try:
                    setattr(self, f, arguments.get(f))
                except ValidationError as e:
                    error_strings.append(e.text.format(f))

            if error_strings:
                raise ValidationError(', '.join(error_strings))
        else:
            raise ValidationError("Empty " + self.__class__.__name__ + " arguments")

    def generate_dict_field_items(self):
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Field):
                yield k, v

    def validate(self):
        pass


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def update_context(self, context):
        context['nclients'] = len(self.client_ids)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        if not ((self.first_name and self.last_name) or
                (self.email and self.phone) or
                (self.birthday and self.gender is not None)):
            raise ValidationError(self.__class__.__name__)

    def get_score_arguments(self):
        return {k: v.field for k, v in self.generate_dict_field_items() if v.valid(self)}

    def update_context(self, context):
        context['has'] = self.get_score_arguments().keys()


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def get_score(request, store, admin):
    if isinstance(request, OnlineScoreRequest):
        return {"score": 42 if admin else scoring.get_score(store, **request.get_score_arguments())}
    if isinstance(request, ClientsInterestsRequest):
        return dict(zip(request.client_ids, map(scoring.get_interests.__get__(store), request.client_ids)))


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = request.account + request.login + SALT

    return hashlib.sha512(msg.encode()).hexdigest() == request.token


def method_handler(request, ctx, store):
    methods = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }

    try:
        method_request = MethodRequest(request.get('body'))
        if not check_auth(method_request):
            return {"error": "Forbidden"}, FORBIDDEN

        method = methods[method_request.method](method_request.arguments)
        method.validate()
        method.update_context(ctx)
        response = get_score(method, store, method_request.is_admin)

    except ValidationError as e:
        return {"error": e.text}, INVALID_REQUEST

    return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    configure_logger(opts.log)
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
