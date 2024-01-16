from re import search
from requests import get
from hashlib import sha1


def check_password_basics(password):

    if len(password) < 8:
        print('Hasło nie spełnia podstawowych założeń.')
        return False

    if not any(char.isdigit() for char in password):
        print('Hasło nie spełnia podstawowych założeń.')
        return False

    if not search("[!@#$%^&*(),.?\":{}|<>]", password):
        print('Hasło nie spełnia podstawowych założeń.')
        return False

    if not any(char.isupper() for char in password):
        print('Hasło nie spełnia podstawowych założeń.')
        return False

    if not any(char.islower() for char in password):
        print('Hasło nie spełnia podstawowych założeń.')
        return False

    print('Hasło spełnia podstawowe założenia :)')
    return True


# check_password_basics('Hasło!')

def is_password_save(password):
    """Take password
    encode it and send request API to download hashes with the same 5 sighs,
    then save it in hashes.txt"""

    hash_password = sha1(password.encode('utf-8'))  # Tworzy hash z naszej linii
    clear_hash = hash_password.hexdigest()          # Pokazuje hash w ładniej formie (hash jest obiektem)
    check_hash = clear_hash[:5]                    # Daje pierwszych 5 znaków naszego hasha

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
                    return
            print(f'Hasło "{password}" jest bezpieczne!')
            save_passwords.write(password)
        else:
            print('Coś poszło nie tak. Sprawdź logi.')      # TODO logi

# is_password_save('][poKL:"')
