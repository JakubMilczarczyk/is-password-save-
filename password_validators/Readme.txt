This package contains few validators to check passwords safety.

It can check length, has number, has Uppercase, has Lowercase, has special character.
If all validators return True the last one check is password leaked.

To check your password, validator send request include 5 first hashes of your password and
get responses as all ends hashes for your 5 first hashes.
If your password has leaked validator print information about leaked and present how much time
has it leaked.



This operation is in method is_valid of class PasswordValidator.


How to use:

To run proces use pip install.........
then enter PasswordValidator.is_valid('"your_password"') and run code.