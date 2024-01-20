from abc import ABC, abstractmethod
from re import search
from requests import get
from hashlib import sha1


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

    def is_valid(self) -> bool:

        return len(self.text) >= self.min_length


class HasDigitCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.isdigit() for char in self.text):
            print(f'Hasło: "{self.text}" nie spełnia podstawowych założeń.')
            return False
        return True


class HasUpperCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.isupper() for char in self.text):
            print(f'Hasło: "{self.text}" nie spełnia podstawowych założeń.')
            return False
        return True


class HasLowerCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not any(char.islower() for char in self.text):
            print(f'Hasło: "{self.text}" nie spełnia podstawowych założeń.')
            return False
        return True


class HasSpecialCharacterValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        if not search("[!@#$%^&*(),.?\":{}|<>]", self.text):
            print(f'Hasło: "{self.text}" nie spełnia podstawowych założeń.')
            return False
        return True


class IsNotPwnedValidator(Validator):
    def __init__(self, text):
        self.text = text

    def is_valid(self):
        """Take password
            encode it and send request API to download hashes with the same 5 sighs,
            then save it in hashes.txt"""

        hash_password = sha1(self.text.encode('utf-8'))     # Tworzy hash z naszej linii
        clear_hash = hash_password.hexdigest()              # Pokazuje hash w ładniej formie (hash jest obiektem)
        check_hash = clear_hash[:5]                         # Daje pierwszych 5 znaków naszego hasha

        url = 'https://api.pwnedpasswords.com/range/' + check_hash

        with get(url) as response_hashes, open('bezpieczne.txt', mode='w') as save_passwords:
            if response_hashes.status_code == 200:
                request_api = response_hashes.text.split('\n')
                # TODO logi print(request_api)
                for response in request_api:
                    rest_of_hash, num_of_use = response.split(':')
                    # TODO logi print(response)
                    if rest_of_hash == clear_hash[5:]:
                        print(f'Hasło wyciekło {num_of_use} razy! \nKaniecznie je zmień!')
                        return False
                print(f'Hasło "{self.text}" jest bezpieczne!')
                save_passwords.write(self.text.strip())
                return True
            else:
                print('Coś poszło nie tak. Sprawdź logi.')  # TODO logi
                return False


class PasswordValidator:
    def __init__(self, password=str):
        self.password = password
        self.validators = [
            LengthValidator(self.password),
            HasDigitCharacterValidator(self.password),
            HasUpperCharacterValidator(self.password),
            HasLowerCharacterValidator(self.password),
            HasSpecialCharacterValidator(self.password),
            IsNotPwnedValidator(self.password)
        ]

    def validate(self):
        if not any(validator is True for validator in self.validators):
            print(f'Hasło: "{self.password}" nie spełnia podstawowych założeń.')
        # dopisz with open i zapis dobrego hasła
        # napisz testy


