

from validators import (
    PasswordValidator,
)


if __name__ == '__main__':
    with open('passwords.txt', encoding='utf8') as passwords, open('bezpieczne.txt', mode='w') as save_passwords:

        count = 0

        for line in passwords:
            count += 1
            print(f'Linia {count}\n Sprawdzam hasło "{line.strip()}".')
            if PasswordValidator(line.strip()).is_valid() is True:
                save_passwords.write(line.strip())
            print('---' * 6, '\n')

    # Dodaje sie znak nowej linii przy bezpiecznych hasłach
    # Pilnować logów czyli takie printy sprawdzające co się dzieje w kodzie.
