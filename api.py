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


class Field:
    def __init__(self, required, nullable, field_type):
        self.required = required
        self.nullable = nullable
        self.field_type = field_type
        self.field = None

    def __get__(self, instance, owner):
        return self.field

    def __set__(self, instance, value):
        if value is None:
            if not self.required:
                self.field = None
                return
            else:
                raise AttributeError("Field '{}' is required, but not provided")

        if not value:
            if self.nullable:
                self.field = self.field_type()
            else:
                raise AttributeError("Field '{}' is not nullable")

        if not isinstance(value, self.field_type):
            raise AttributeError("Field '{}' must be of " + str(self.field_type))

        if self.value_check(value):
            self.field = value
        else:
            raise AttributeError("Field '{}' is not valid")

    def value_check(self, value):
        return True

    def valid(self):
        return bool(self.field)


class CharField(Field):
    def __init__(self, required, nullable):
        Field.__init__(self, required, nullable, str)


class ArgumentsField(Field):
    def __init__(self, required, nullable):
        Field.__init__(self, required, nullable, dict)


class EmailField(CharField):
    def __init__(self, required, nullable):
        CharField.__init__(self, required, nullable)

    def value_check(self, value):
        return '@' in value


class PhoneField(CharField):
    def __init__(self, required, nullable):
        CharField.__init__(self, required, nullable)

    def __set__(self, instance, value):
        if value and isinstance(value, int):
            value = str(value)

        CharField.__set__(self, instance, value)

    def value_check(self, value):
        return value.isdecimal() and len(value) == 11 and value.startswith('7')


class DateField(CharField):
    def __init__(self, required, nullable):
        CharField.__init__(self, required, nullable)

    def value_check(self, value):
        dmy = value.split('.')
        return len(dmy) == 3 and len(value) == 10 and all(s.isdecimal() for s in dmy)


class BirthDayField(DateField):
    def __init__(self, required, nullable):
        DateField.__init__(self, required, nullable)

    def value_check(self, value):
        if DateField.value_check(self, value):
            b_day = datetime.date(*reversed([int(s) for s in value.split('.')]))
            delta = datetime.datetime.now().date() - b_day
            return delta.days / 365 <= 70

        return False


class GenderField(Field):
    def __init__(self, required, nullable):
        Field.__init__(self, required, nullable, int)

    def value_check(self, value):
        return 0 <= value <= 2

    def valid(self):
        return self.field is not None


class ClientIDsField(Field):
    def __init__(self, required):
        Field.__init__(self, required, False, list)

    def value_check(self, value):
        return all(isinstance(n, int) for n in value)


class Request:
    def __init__(self, arguments, name):
        if arguments:
            error_strings = []
            field_names = [k for k, v in self.__class__.__dict__.items() if isinstance(v, Field)]

            for f in field_names:
                try:
                    setattr(self, f, arguments.get(f))
                except AttributeError as e:
                    error_strings.append(str(e).format(f))

            if not self.validate():
                error_strings.append(name + " body validation failed")

            if error_strings:
                raise AttributeError(', '.join(error_strings))
        else:
            raise AttributeError("Empty " + name.lower())

    def validate(self):
        return True


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, arguments):
        Request.__init__(self, arguments, 'Arguments')

    def get_context(self):
        return self.client_ids


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        Request.__init__(self, arguments, 'Arguments')

    def validate(self):
        return (self.first_name and self.last_name) or \
                    (self.email and self.phone) or \
                    (self.birthday and self.gender is not None)

    def get_context(self):
        return {k: v.field for k, v in self.__class__.__dict__.items()
                if not k.startswith('__') and not hasattr(v, '__call__') and v.valid()}


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, json_request):
        Request.__init__(self, json_request, 'Request')

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = request.account + request.login + SALT

    return hashlib.sha512(msg.encode()).hexdigest() == request.token


def method_handler(request, ctx, store):
    response, code = None, OK

    methods = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }

    try:
        method_request = MethodRequest(request.get('body'))
        if not check_auth(method_request):
            raise PermissionError

        context = methods[method_request.method](method_request.arguments).get_context()
        if isinstance(context, dict):
            ctx['has'] = context.keys()
            response = {"score": 42 if check_auth(method_request) else scoring.get_score(store, **context)}
        else:
            ctx['nclients'] = len(context)
            response = dict(zip(context, map(scoring.get_interests.__get__(store), context)))

    except AttributeError as e:
        response, code = {"error": str(e)}, INVALID_REQUEST
    except PermissionError:
        response, code = {"error": "Forbidden"}, FORBIDDEN

    return response, code


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
