import abc
import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer

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


class Field(abc.ABC):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    @abc.abstractmethod
    def validate(self, value):
        pass


class CharField(Field):
    def validate(self, value):
        if self.required and (value is None or value == ''):
            return False
        if not self.nullable and value is None:
            return False
        return isinstance(value, str)


class EmailField(CharField):
    def validate(self, value):
        if not super().validate(value):
            return False
        if '@' not in value:
            return False
        return True


class PhoneField(Field):
    def validate(self, value):
        if self.required and (value is None or value == ''):
            return False
        if value is not None and not isinstance(value, str):
            return False
        return True


class DateField(Field):
    def validate(self, value):
        if self.required and (value is None or value == ''):
            return False
        if value is not None:
            try:
                datetime.datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                return False
        return True


class BirthDayField(DateField):
    def validate(self, value):
        if not super().validate(value):
            return False
        if value is not None:
            birth_date = datetime.datetime.strptime(value, "%Y-%m-%d")
            return birth_date < datetime.datetime.now()
        return True


class ArgumentsField(Field):
    def __init__(self, required=False, nullable=False, fields=None):
        super().__init__(required, nullable)
        self.fields = fields or {}

    def validate(self, value):
        if self.required and (value is None or not isinstance(value, dict)):
            return False
        if value is not None:
            if not isinstance(value, dict):
                return False
            for field_name, field in self.fields.items():
                field_value = value.get(field_name, None)
                if not field.validate(field_value):
                    return False
        return True


class GenderField(Field):
    def validate(self, value):
        if value is not None and value not in GENDERS:
            return False
        return True


class ClientIDsField(Field):
    def validate(self, value):
        if self.required and (value is None or not isinstance(value, list) or len(value) == 0):
            return False
        return True


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest:
    def __init__(self, account=None, login=None, token=None, method=None, arguments=None):
        self.account = account
        self.login = login
        self.token = token
        self.method = method
        self.arguments = arguments

    def validate(self):
        errors = []
        if not self.login:
            errors.append("Login is required")
        if not self.method:
            errors.append("Method is required")
        if not self.token:
            errors.append("Token is required")
        return len(errors) == 0, errors or None



def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    response, code = None, None
    method_request = MethodRequest(**request['body'])
    is_valid, error = method_request.validate()
    if not is_valid:
        return {"error": error}, INVALID_REQUEST

    if check_auth(method_request):
        response = {"status": "success"}
        code = OK
    else:
        return {"error": "Unauthorized"}, FORBIDDEN

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
        except Exception as e:
            logging.error("Failed to read request: %s", e)
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
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
