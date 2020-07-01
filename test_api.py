import re
import datetime
import hashlib

import pytest

import api
import store


tf_list = [True, False]


def set_valid_auth(request):
    if request.get("login") == api.ADMIN_LOGIN:
        msg = datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT
    else:
        msg = request.get("account", "") + request.get("login", "") + api.SALT

    request["token"] = hashlib.sha512(msg.encode()).hexdigest()


@pytest.fixture
def instance(request):
    class TestInstanceObject:
        pass

    return TestInstanceObject()


@pytest.fixture(params=[int, str, dict, list])
def case_type(request):
    yield request.param


@pytest.fixture
def valid_interests_request(request):
    req = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": {}}
    set_valid_auth(req)
    return req


@pytest.fixture
def valid_score_request(request):
    req = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {}}
    set_valid_auth(req)
    return req


@pytest.mark.parametrize('case_nullable', tf_list, ids=['(nullable={})'.format(tf) for tf in tf_list])
@pytest.mark.parametrize('case_required', tf_list, ids=['(required={})'.format(tf) for tf in tf_list])
def test_field_construction(case_required, case_nullable, case_type):
    f = api.Field(case_required, case_nullable, case_type)
    assert not f.field


@pytest.mark.parametrize('case_nullable', tf_list, ids=['(nullable={})'.format(tf) for tf in tf_list])
def test_field_set_none_required(case_nullable, case_type, instance):
    f = api.Field(True, case_nullable, case_type)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, None)


@pytest.mark.parametrize('case_nullable', tf_list, ids=['(nullable={})'.format(tf) for tf in tf_list])
def test_field_set_none_not_required(case_nullable, case_type, instance):
    f = api.Field(False, case_nullable, case_type)
    f.__set__(instance, None)
    assert f.field
    assert not f.field[instance]


@pytest.mark.parametrize('case_required', tf_list, ids=['(required={})'.format(tf) for tf in tf_list])
def test_field_set_nullable(case_required, case_type, instance):
    f = api.Field(case_required, True, case_type)
    f.__set__(instance, case_type())
    assert f.field
    assert not f.field[instance]


@pytest.mark.parametrize('case_required', tf_list, ids=['(required={})'.format(tf) for tf in tf_list])
def test_field_set_non_nullable(case_required, case_type, instance):
    f = api.Field(case_required, False, case_type)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, case_type())


@pytest.mark.parametrize('case_value', ['abc', -4, [1, 2, 3], {'a': 1, 'b': 2}, int, str, True, (1,)])
def test_field_set_wrong_type(case_type, case_value, instance):
    f = api.Field(True, False, case_type)
    if not isinstance(case_value, case_type):
        with pytest.raises(api.ValidationError, match=str(case_type)):
            f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['abc', -4, [1, 2, 3], {'a': 1, 'b': 2}, int, str, True, (1,)])
def test_field_get(case_type, case_value, instance):
    f = api.Field(True, False, case_type)
    if isinstance(case_value, case_type):
        f.__set__(instance, case_value)
        assert f.__get__(instance, None) == case_value


@pytest.mark.parametrize('case_value', [-4, [1, 2, 3], {'a': 1, 'b': 2}, int, str, True, (1,)])
def test_char_field_set_wrong(case_value, instance):
    f = api.CharField(True, False)
    with pytest.raises(api.ValidationError, match=str(str)):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['abc', -4, [1, 2, 3], int, str, True, (1,)])
def test_arguments_field_set_wrong(case_value, instance):
    f = api.ArgumentsField(True, False)
    with pytest.raises(api.ValidationError, match=str(dict)):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', [-4, [1, 2, 3], {'a': 1, 'b': 2}, int, str, True, (1,)])
def test_email_field_set_non_str(case_value, instance):
    f = api.EmailField(True, False)
    with pytest.raises(api.ValidationError, match=str(str)):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['abc', '123', 'spam'])
def test_email_field_set_wrong_text(case_value, instance):
    f = api.EmailField(True, False)
    with pytest.raises(api.ValidationError, match='@'):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['@', 'test@test.ry', 'abc@', ' @ '])
def test_email_field_set_ok(case_value, instance):
    f = api.EmailField(True, False)
    f.__set__(instance, case_value)
    assert f.__get__(instance, None) == case_value


@pytest.mark.parametrize('case_value', ['abc', '123', '12345678901', '7890', 712345678907, '7123456789012345'])
def test_phone_field_set_wrong_text(case_value, instance):
    f = api.PhoneField(True, False)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', [71234567890, '70987654321'])
def test_phone_field_set_ok(case_value, instance):
    f = api.PhoneField(True, False)
    f.__set__(instance, case_value)
    assert f.__get__(instance, None) == str(case_value)


@pytest.mark.parametrize('case_value', ['abc', 'ab.cdefghi', '01.02.123c', '01.0234567', '01.02.03.04'])
def test_date_field_set_wrong(case_value, instance):
    f = api.DateField(True, False)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['01.02.1234', '23.07.1467'])
def test_date_field_set_ok(case_value, instance):
    f = api.DateField(True, False)
    f.__set__(instance, case_value)
    assert f.__get__(instance, None).strftime('%d.%m.%Y') == case_value


@pytest.mark.parametrize('case_value', ['01.02.1234', '23.07.1467'])
def test_birthday_field_set_wrong(case_value, instance):
    f = api.BirthDayField(True, False)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', ['01.02.2000', '23.07.1970'])
def test_birthday_field_set_ok(case_value, instance):
    f = api.BirthDayField(True, False)
    f.__set__(instance, case_value)
    assert f.__get__(instance, None).strftime('%d.%m.%Y') == case_value


@pytest.mark.parametrize('case_value', [-1, 3, 1234])
def test_gender_field_set_wrong(case_value, instance):
    f = api.GenderField(True, True)
    with pytest.raises(api.ValidationError):
        f.__set__(instance, case_value)


@pytest.mark.parametrize('case_value', [0, 1, 2])
def test_gender_field_set_ok(case_value, instance):
    f = api.GenderField(True, True)
    f.__set__(instance, case_value)
    assert f.__get__(instance, None) == case_value


def test_empty_request():
    result, code = api.method_handler({"body": {}, "headers": {}}, {}, store.Store(max_attempts=10))
    assert 'error' in result
    assert result['error'] == 'Empty MethodRequest arguments'
    assert code == api.INVALID_REQUEST


@pytest.mark.parametrize('body_value', [
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}}
    ], ids=['no token', 'bad token', 'admin & no token'])
def test_bad_auth(body_value):
    result, code = api.method_handler({"body": body_value, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.FORBIDDEN
    assert 'error' in result
    assert result['error'] == 'Forbidden'


@pytest.mark.parametrize('body_value', [
    {"account": "horns&hoofs", "login": "h&f", "method": "online_score"},
    {"account": "horns&hoofs", "login": "h&f", "arguments": {}},
    {"account": "horns&hoofs", "method": "online_score", "arguments": {}}
    ], ids=['no arguments & token', 'no method & token', 'no login & token'])
def test_invalid_method_request(body_value):
    result, code = api.method_handler({"body": body_value, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.INVALID_REQUEST
    assert 'error' in result
    assert re.search(r"Field '[a-z_]*' is required, but not provided", result['error'])


@pytest.mark.parametrize('arguments_value', [{}])
def test_empty_score_request(arguments_value, valid_score_request):
    valid_score_request['arguments'] = arguments_value
    result, code = api.method_handler({"body": valid_score_request, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.INVALID_REQUEST
    assert 'error' in result
    assert result['error'] == 'Empty OnlineScoreRequest arguments'


@pytest.mark.parametrize('arguments_value', [
    {"phone": "79175002040"},
    {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
    {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 's'}
])
def test_invalid_score_request(arguments_value, valid_score_request):
    valid_score_request['arguments'] = arguments_value
    result, code = api.method_handler({"body": valid_score_request, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.INVALID_REQUEST
    assert 'error' in result
    assert result['error'] == 'OnlineScoreRequest arguments body validation failed'


@pytest.mark.parametrize('arguments_value', [
    {"phone": "89175002040", "email": "stupnikov@otus.ru"},
    {"phone": "79175002040", "email": "stupnikovotus.ru"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"}
])
def test_error_score_request(arguments_value, valid_score_request):
    valid_score_request['arguments'] = arguments_value
    result, code = api.method_handler({"body": valid_score_request, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.INVALID_REQUEST
    assert 'error' in result
    assert re.search(r"Field '[a-z_]*' is not valid", result['error'])


@pytest.mark.parametrize('arguments_value', [
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
     "first_name": "s", "last_name": 2}
])
def test_error_type_score_request(arguments_value, valid_score_request):
    valid_score_request['arguments'] = arguments_value
    result, code = api.method_handler({"body": valid_score_request, "headers": {}}, {}, store.Store(max_attempts=10))
    assert code == api.INVALID_REQUEST
    assert 'error' in result
    assert re.search(r"Field '[a-z_]*' must be of ", result['error'])


@pytest.mark.parametrize('arguments_value', [
    {"phone": "79175002040", "email": "stupnikov@otus.ru"},
    {"phone": 79175002040, "email": "stupnikov@otus.ru"},
    {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
    {"gender": 0, "birthday": "01.01.2000"},
    {"gender": 2, "birthday": "01.01.2000"},
    {"first_name": "a", "last_name": "b"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
     "first_name": "a", "last_name": "b"}
])
def test_ok_score_request(arguments_value, valid_score_request):
    valid_score_request['arguments'] = arguments_value
    st = store.Store(max_attempts=10)
    result, code = api.method_handler({"body": valid_score_request, "headers": {}}, {}, st)
    assert code == api.OK
    assert 'error' not in result
    assert 'score' in result


def test_ok_score_admin_request():
    arguments = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
    request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
    set_valid_auth(request)
    st = store.Store(max_attempts=10)
    result, code = api.method_handler({"body": request, "headers": {}}, {}, st)
    assert code == api.OK
    assert 'score' in result
    assert result['score'] == 42


@pytest.mark.parametrize('arguments_value', [
    {},
    {"date": "20.07.2017"},
    {"client_ids": [], "date": "20.07.2017"},
    {"client_ids": {1: 2}, "date": "20.07.2017"},
    {"client_ids": ["1", "2"], "date": "20.07.2017"},
    {"client_ids": [1, 2], "date": "XXX"}
])
def test_invalid_interests_request(arguments_value, valid_interests_request):
    valid_interests_request['arguments'] = arguments_value
    st = store.Store(max_attempts=10)
    result, code = api.method_handler({"body": valid_interests_request, "headers": {}}, {}, st)
    assert code == api.INVALID_REQUEST
    assert 'error' in result
