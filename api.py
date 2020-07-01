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
import store

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


class ApiException(Exception):
    def __init__(self, what):
        self.what = what


class UnprovidedFieldError(ApiException):
    def __init__(self):
        ApiException.__init__(self, "Field '{0}' is required, but not provided")


class NullableFieldError(ApiException):
    def __init__(self):
        ApiException.__init__(self, "Field '{0}' is not nullable")


class FieldTypeError(ApiException):
    def __init__(self, type):
        ApiException.__init__(self, "Field '{0}' must be of " + str(type))


class InvalidFieldError(ApiException):
    def __init__(self, text):
        ApiException.__init__(self, "Field '{0}' is not valid. " + text)


class ValidationError(ApiException):
    def __init__(self, text):
        ApiException.__init__(self, text + " arguments body validation failed")


class Field:
    def __init__(self, required, nullable, field_type):
        self.required = required
        self.nullable = nullable
        self.field_type = field_type
        self.field = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.field.get(instance)

    def __set__(self, instance, value):
        if value is None:
            if not self.required:
                self.field[instance] = None
                return
            else:
                raise UnprovidedFieldError

        if not value:
            if self.nullable:
                self.field[instance] = self.field_type()
            else:
                raise NullableFieldError

        if not isinstance(value, self.field_type):
            raise FieldTypeError(self.field_type)

        self.value_check_and_assign(instance, value)

    def value_check_and_assign(self, instance, value):
        self.field[instance] = value

    def valid(self, instance):
        return bool(self.field.get(instance))


class CharField(Field):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, str)


class ArgumentsField(Field):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, dict)


class EmailField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def value_check_and_assign(self, instance, value):
        if '@' in value:
            self.field[instance] = value
        else:
            raise InvalidFieldError("'@' symbol not present in the analysed string")


class PhoneField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def __set__(self, instance, value):
        if value and isinstance(value, int):
            value = str(value)

        super().__set__(instance, value)

    def value_check_and_assign(self, instance, value):
        error_strings = []

        if not value.isdecimal():
            error_strings.append("Not a decimal value provided")

        if len(value) != 11:
            error_strings.append("Wrong phone number length")

        if not value.startswith('7'):
            error_strings.append("The phone number must begin with '7'")

        if error_strings:
            raise InvalidFieldError('; '.join(error_strings))

        self.field[instance] = value


class DateField(CharField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    @staticmethod
    def date_check(value):
        error_strings = []
        dmy = value.split('.')

        if not len(dmy) == 3:
            error_strings.append("Date format must have exactly 3 positions separated with '.'")

        if not len(value) == 10:
            error_strings.append("Date format length must be exactly 10 chars")

        if any(not s.isdecimal() for s in dmy):
            error_strings.append("Date positions must be decimal numbers")

        return error_strings

    def value_check_and_assign(self, instance, value):
        error_strings = self.date_check(value)

        if error_strings:
            raise InvalidFieldError('; '.join(error_strings))

        self.field[instance] = value


class BirthDayField(DateField):
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def value_check_and_assign(self, instance, value):
        error_strings = self.date_check(value)
        if not error_strings:
            b_day = datetime.date(*reversed([int(s) for s in value.split('.')]))
            delta = datetime.datetime.now().date() - b_day

            if delta.days / 365 > 70:
                error_strings.append("The person's age is greater then 70 years")

        if error_strings:
            raise InvalidFieldError('; '.join(error_strings))

        self.field[instance] = value


class GenderField(Field):
    def __init__(self, required, nullable):
        super().__init__(required, nullable, int)

    def value_check_and_assign(self, instance, value):
        if 0 <= value <= 2:
            self.field[instance] = value
        else:
            raise InvalidFieldError("Gender id must be between 0 and 2")

    def valid(self, instance):
        return self.field.get(instance) is not None


class ClientIDsField(Field):
    def __init__(self, required):
        super().__init__(required, False, list)

    def value_check(self, value):
        return all(isinstance(n, int) for n in value)

    def value_check_and_assign(self, instance, value):
        error_strings = [str(v) + " is not a valid integer" for v in value if not isinstance(v, int)]

        if error_strings:
            raise InvalidFieldError('; '.join(error_strings))

        self.field[instance] = value


class Request:
    def __init__(self, arguments):
        if arguments:
            error_strings = []
            field_names = [k for k, v in self.generate_dict_field_items()]

            for f in field_names:
                try:
                    setattr(self, f, arguments.get(f))
                except ApiException as e:
                    error_strings.append(e.what.format(f))

            if error_strings:
                raise AttributeError(', '.join(error_strings))
        else:
            raise AttributeError("Empty " + self.__class__.__name__ + " arguments")

    def generate_dict_field_items(self):
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Field):
                yield k, v

    def validate(self):
        pass


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, arguments):
        super().__init__(arguments)

    def update_context(self, context):
        context['nclients'] = len(self.client_ids)

    def get_response(self, storage, admin):
        return dict(zip(self.client_ids, map(scoring.get_interests.__get__(storage), self.client_ids)))


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        super().__init__(arguments)

    def validate(self):
        if not ((self.first_name and self.last_name) or
                (self.email and self.phone) or
                (self.birthday and self.gender is not None)):
            raise ValidationError(self.__class__.__name__)

    def get_score_arguments(self):
        return {k: v.field[self] for k, v in self.generate_dict_field_items() if v.valid(self)}

    def update_context(self, context):
        context['has'] = self.get_score_arguments().keys()

    def get_response(self, storage, admin):
        return {"score": 42 if admin else scoring.get_score(storage, **self.get_score_arguments())}


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, json_request):
        super().__init__(json_request)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        msg = request.account + request.login + SALT

    return hashlib.sha512(msg.encode()).hexdigest() == request.token


def method_handler(request, ctx, storage):
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
        response = method.get_response(storage, method_request.is_admin)

    except ValidationError as e:
        return {"error": e.what}, INVALID_REQUEST
    except Exception as e:
        return {"error": str(e)}, INVALID_REQUEST

    return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = store.Store(max_attempts=10)

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
