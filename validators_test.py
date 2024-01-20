from requests import get
from validators import (
    LengthValidator,
    HasDigitCharacterValidator,
    HasUpperCharacterValidator,
    HasLowerCharacterValidator,
    HasSpecialCharacterValidator,
    IsNotPwnedValidator,
    PasswordValidator
)


def test_good_length_validator():
    password = LengthValidator('password')

    result = password.is_valid()

    assert result is True

    password = LengthValidator('pass', 3)

    result = password.is_valid()

    assert result is True


def test_bad_length_validator():
    password = LengthValidator('pass', 8)

    result = password.is_valid()

    assert result is False


def test_good_has_digit_validator():
    password = HasDigitCharacterValidator('password1')

    resoult = password.is_valid()

    assert resoult is True


def test_bad_has_digit_validator():
    password = HasDigitCharacterValidator('password')

    resoult = password.is_valid()

    assert resoult is False


def test_good_has_upper_validator():
    password = HasUpperCharacterValidator('Password')

    resoult = password.is_valid()

    assert resoult is True


def test_bad_has_upper_validator():
    password = HasUpperCharacterValidator('password')

    resoult = password.is_valid()

    assert resoult is False


def test_good_has_lower_validator():
    password = HasLowerCharacterValidator('Password1!')

    resoult = password.is_valid()

    assert resoult is True


def test_bad_has_lower_validator():
    password = HasLowerCharacterValidator('PASSWORD1!')

    resoult = password.is_valid()

    assert resoult is False


def test_good_has_special_character_validator():
    password = HasSpecialCharacterValidator('Password1!')

    resoult = password.is_valid()

    assert resoult is True


def test_bad_has_special_character_validator():
    password = HasSpecialCharacterValidator('Password1')

    resoult = password.is_valid()

    assert resoult is False


def test_request(requests_mock):    # TODO ogarnać ten test
    password = IsNotPwnedValidator('Test')
    data = '00E15AD182216C9D32E37AD227083C11A6D:2\n01AC1B60A56131BEC102808D32D4DA91E29:11\n'
    requests_mock.get('https://api.pwnedpasswords.com/range/640ab', text=data)
    assert password.is_valid() is True

# def test_wrong_password():
#     password1 = 'zaq1@W'
#     password2 = 'zaq!@WSX'
#     password3 = 'zaq12WSX'
#     password4 = 'zaq1@wsx'
#     password5 = 'ZAQ1@WSX'
#
#     checking = (
#         check_password_basics(password1),
#         check_password_basics(password2),
#         check_password_basics(password3),
#         check_password_basics(password4),
#         check_password_basics(password5)
#     )
#
#     assert checking == (False, False, False, False, False)
#
#
# def check_first_line_low_then(x):
#     response = get('https://api.pwnedpasswords.com/range/640ab')
#     counter = response.text.splitlines()[0].split(':')[1]
#
#     if int(counter) >= x:
#         return True
#     else:
#         return False
#
#
# def test_request(requests_mock):
#     data = '00E15AD182216C9D32E37AD227083C11A6D:2\n01AC1B60A56131BEC102808D32D4DA91E29:11\n'
#     requests_mock.get('https://api.pwnedpasswords.com/range/640ab', text=data)
#     assert check_first_line_low_then(1) == True
#
#
