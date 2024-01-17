from functions import is_password_save, check_password_basics
from requests import get


def test_good_password():
    password = 'zaq1@WSX'

    assert check_password_basics(password) == True


def test_wrong_password():
    password1 = 'zaq1@W'
    password2 = 'zaq!@WSX'
    password3 = 'zaq12WSX'
    password4 = 'zaq1@wsx'
    password5 = 'ZAQ1@WSX'

    checking = (
        check_password_basics(password1),
        check_password_basics(password2),
        check_password_basics(password3),
        check_password_basics(password4),
        check_password_basics(password5)
    )

    assert checking == (False, False, False, False, False)


def check_first_line_low_then(x):
    response = get('https://api.pwnedpasswords.com/range/640ab')
    counter = response.text.splitlines()[0].split(':')[1]

    if int(counter) >= x:
        return True
    else:
        return False


def test_request(requests_mock):
    data = '00E15AD182216C9D32E37AD227083C11A6D:2\n01AC1B60A56131BEC102808D32D4DA91E29:11\n'
    requests_mock.get('https://api.pwnedpasswords.com/range/640ab', text=data)
    assert check_first_line_low_then(1) == True


