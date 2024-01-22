from abc import ABC, abstractmethod
from re import search
from requests import get
from hashlib import sha1


class ValidationError(Exception):
    pass


class Validator(ABC):
    @abstractmethod
    def __init__(self, text):
        pass

    @abstractmethod
    def is_valid(self):
        pass


class LengthValidator(Validator):
    def __init__(self, text, min_length=8):
        self.text = text
        self.min_length = min_length

    def is_valid(self):

        if len(self.text) >= self.min_length:
            return True
        else:
            raise ValidationError(f'Password: "{self.text}" is too short!')


class HasDigitCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.isdigit() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has not number.')
        return True


class HasUpperCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.isupper() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has not Uppercase character!')
        return True


class HasLowerCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.islower() for char in self.text):
            raise ValidationError(f'Password: "{self.text}" has nat Lowercase character!')
        return True


class HasSpecialCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not search("[!@#$%^&*( ),.?\":{}|<>]", self.text):
            raise ValidationError(f'Password: "{self.text}" has not special character!')
        return True


class IsNotPwnedValidator(Validator):
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        """Take password
            encode it and send request API to download hashes with the same 5 sighs,
            then save it in hashes.txt"""

        hash_password = sha1(self.password.encode('utf-8'))     # Tworzy hash z naszej linii
        clear_hash = hash_password.hexdigest()              # Pokazuje hash w ładniej formie (hash jest obiektem)
        check_hash = clear_hash[:5]                         # Daje pierwszych 5 znaków naszego hasha

        url = 'https://api.pwnedpasswords.com/range/' + check_hash

        with get(url) as response_hashes, open('bezpieczne.txt', mode='w') as save_passwords:
            if response_hashes.status_code == 200:
                request_api = response_hashes.text.split()
                # TODO logi print(request_api)
                for response in request_api:
                    rest_of_hash, num_of_use = response.split(':')
                    # TODO logi print(response)
                    if rest_of_hash == clear_hash[5:]:
                        raise ValidationError(f'Password: "{self.password}" has leaked {num_of_use} times!!!')
                print(f'Password "{self.password}" is save!')
                save_passwords.write(self.password.strip())
                return True
            else:
                print('Coś poszło nie tak. Sprawdź logi.')  # TODO logi
                return False


class PasswordValidator(Validator):
    def __init__(self, password=str):
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
        if all(validator is True for validator in self.validators):
            return True
        return False
        # # dopisz with open i zapis dobrego hasła
        # for class_name in self.validators:
        #     validator = class_name(self.password)
        #     if validator.is_valid() is False:
        #         return False
        #     return True


