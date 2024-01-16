from functions import check_password_basics, is_password_save
from hashlib import sha1

# with open('passwords.txt', encoding='utf8') as passwords:
#     for line in passwords:
#         print(line.strip())

with open('passwords.txt', encoding='utf8') as passwords, open('correct_passwords.txt', mode='w') as correct_passwords:

    count = 0

    for line in passwords:
        count += 1
        print(f'Linia {count}\n Sprawdzam hasło "{line.strip()}".')

        if check_password_basics(line) is True:
            correct_passwords.write(line)
        print('---' * 6, '\n')

    print(
        'Zakończono sprawdzanie poprawności haseł.\n'
        'Hasła zostały zapisane w pliku correct_passwords.txt\n'
        'Przystępuje do weryfikacji bezpieczeństwa haseł.')

with open('correct_passwords.txt', mode='r') as correct_passwords:
    for line in correct_passwords:
        is_password_save(line)


# Dodaje sie znak nowej linii przy bezpiecznych hasłach
# Pilnować logów czyli takie printy sprawdzające co się dzieje w kodzie.
