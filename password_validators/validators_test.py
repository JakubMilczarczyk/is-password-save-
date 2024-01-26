import pytest
from validators import (
    LengthValidator,
    HasDigitCharacterValidator,
    HasUpperCharacterValidator,
    HasLowerCharacterValidator,
    HasSpecialCharacterValidator,
    IsNotPwnedValidator,
    ValidationError,
    PasswordValidator
)


def test_length_validator_positive():
    password = LengthValidator('password')

    result = password.is_valid()

    assert result is True

    password = LengthValidator('pass', 3)

    result = password.is_valid()

    assert result is True


def test_length_validator_negative():
    password = LengthValidator('pass', 8)

    with pytest.raises(ValidationError) as error:
        password.is_valid()

    assert f'Password: "pass" is too short!' in str(error.value)


def test_has_digit_validator_positive():
    password = HasDigitCharacterValidator('password1')

    result = password.is_valid()

    assert result is True


def test_has_digit_validator_negative():
    password = HasDigitCharacterValidator('password')

    with pytest.raises(ValidationError) as error:
        password.is_valid()
        assert f'Password: "password" has not number.' in str(error.value)


def test_has_upper_validator_positive():
    password = HasUpperCharacterValidator('Password')

    result = password.is_valid()

    assert result is True


def test_has_upper_validator_negative():
    password = HasUpperCharacterValidator('password')

    with pytest.raises(ValidationError) as error:
        password.is_valid()
        assert f'Password: "password" has not Uppercase character!' in str(error.value)


def test_has_lower_validator_positive():
    password = HasLowerCharacterValidator('Password1!')

    result = password.is_valid()

    assert result is True


def test_has_lower_validator_negative():
    password = HasLowerCharacterValidator('PASSWORD1!')

    with pytest.raises(ValidationError) as error:
        password.is_valid()
        assert f'Password: "PASSWORD1!" has nat Lowercase character!' in str(error.value)


def test_has_special_character_validator_positive():
    password = HasSpecialCharacterValidator('Password1[')

    result = password.is_valid()

    assert result is True


def test_has_special_character_validator_negative():

    with pytest.raises(ValidationError) as error:
        password = HasSpecialCharacterValidator('Password1')
        password.is_valid()
        assert f'Password: "Password1" has not special character!' in str(error.value)


def test_is_not_pwned_validator_positive(requests_mock):
    password = IsNotPwnedValidator('Test')
    data = '00E15AD182216C9D32E37AD227083C11A6D:2\n01AC1B60A56131BEC102808D32D4DA91E29:11\n'

    requests_mock.get('https://api.pwnedpasswords.com/range/640ab', text=data)
    assert password.is_valid() is True


def test_is_not_pwned_validator_negative(requests_mock):
    data = '00E15AD182216C9D32E37AD227083C11A6D:2\n2bae07bedc4c163f679a746f7ab7fb5d1fa:11'

    with pytest.raises(ValidationError) as error:
        password_validator = IsNotPwnedValidator('Test')
        requests_mock.get('https://api.pwnedpasswords.com/range/640ab', text=data)
        password_validator.is_valid()
        assert f'Password: "Test" has leaked 11 times!!!' in str(error.value)


def test_password_validator_positive():
    password = PasswordValidator('Klak12Gs!')

    assert password.is_valid() is True


def test_password_validator_negative():
    with pytest.raises(ValidationError) as error:
        password = PasswordValidator('Password!')
        password.is_valid()

        assert f'Password: "Password!" has not number.' in str(error.value)
