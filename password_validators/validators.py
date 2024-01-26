"""Validators to check passwords"""
from abc import ABC, abstractmethod
from hashlib import sha1
from requests import get


class ValidationError(Exception):
    """Exception for validation error"""


# class TimeoutError(Exception):


class Validator(ABC):
    """Interface for validators"""
    @abstractmethod
    def __init__(self, text):
        """Force to implement __init__ method"""

    @abstractmethod
    def is_valid(self):
        """Force to implement is_valid method"""


class LengthValidator(Validator):
    """Length validator"""
    def __init__(self, text, min_length=8):
        self.text = text
        self.min_length = min_length

    def is_valid(self):
        """
        Compare given text length with min_length
        if text >= min_length: return True
        if text < min_length: raise error
        """

        if len(self.text) >= self.min_length:
            return True
        raise ValidationError(f'Password: "{self.text}" is too short!')


class HasDigitCharacterValidator(Validator):
    """Digit validator"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """
        check all characters in text
        :return:
        if any character is digit return True
        if no digit in text raise error
        """
        if not any(char.isdigit() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has not number.')
        return True


class HasUpperCharacterValidator(Validator):
    """Has Uppercase character Validator"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """
        check all characters in text
        :return:
        if any character is Uppercase return True
        if no Uppercase character in text raise error
        """
        if not any(char.isupper() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has not Uppercase character!')
        return True


class HasLowerCharacterValidator(Validator):
    """Has Lowercase character validator"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """
        check all characters in text
        :return:
        if any character is Lowercase return True
        if no Lowercase character in text raise error
        """
        if not any(char.islower() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has not Lowercase character!')
        return True


class HasSpecialCharacterValidator(Validator):
    """Has special character validator"""
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """
        check all characters in text
        :return:
        if all character is alphanumeric raise error
        if no all character is alphanumeric in text return True
        """
        generator_expression = (character.isalnum() for character in self.text)
        if all(generator_expression) is True:
            raise ValidationError(f'Password: "{self.text}" has not special character!')
        return True


class IsNotPwnedValidator(Validator):
    """Is not Pwned validator"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """
        Take password
        encode it and send request API to download hashes with the same 5 sighs,
        :return:
        Check responses 5: hashes,
        if rest_of_hash == clear_hash[5:] raise error
        if responses hashes != clear_hash return True
        """

        hash_password = sha1(self.password.encode('utf-8'))
        clear_hash = hash_password.hexdigest()
        check_hash = clear_hash[:5]

        url = 'https://api.pwnedpasswords.com/range/' + check_hash
        timeout_seconds = 5

        with get(url, timeout=timeout_seconds) as response_hashes:
            if response_hashes.status_code == 200:
                request_api = response_hashes.text.split()

                for response in request_api:
                    rest_of_hash, num_of_use = response.split(':')
                    if rest_of_hash == clear_hash[5:]:
                        raise ValidationError(
                            f'Password: "{self.password}" has leaked {num_of_use} times!!!'
                        )
                    print(f'Password "{self.password}" is save!')
                    return True
            print(f'Coś poszło nie tak. Sprawdź logi {response_hashes.status_code}.')
            return False


class PasswordValidator(Validator):
    """Password Validator"""
    def __init__(self, password):
        self.password = password
        self.validators = [
            LengthValidator,
            HasDigitCharacterValidator,
            HasUpperCharacterValidator,
            HasLowerCharacterValidator,
            HasSpecialCharacterValidator,
            IsNotPwnedValidator
        ]

    def is_valid(self):
        """
        raise all validators one by one with the same input password
        :return:
        if all validators returns True, return True
        if any  validator return False, return False
        """
        if all(validator(self.password).is_valid() is True for validator in self.validators):
            return True
        return False
