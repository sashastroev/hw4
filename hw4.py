import bcrypt
import uuid


class User:
    """
    Базовый класс, представляющий пользователя.
    """
    users = [] # Список для хранения всех пользователей
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = User.hash_password(password)

        User.users.append(self)

    @staticmethod
    def hash_password(password):
        """
        Хешируем пароль
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


    @staticmethod
    def check_password(stored_password, provided_password):
        """
        Проверка пароля.
        """
        return bcrypt.checkpw(provided_password.encode(), stored_password)

    def get_details(self):
        return f'Данные пользователя\nИмя: {self.username}\nEmail: {self.email}\nPassword: {self.password}'


class Customer(User):
    """
    Класс, представляющий клиента, наследующий класс User.
    """

    def __init__(self, username, email, password, address):
        super().__init__(username, email, password)
        self.address = address

    def get_details(self):
        return super().get_details() + f'\nАдрес: {self.address}'


class Admin(User):
    """
    Класс, представляющий администратора, наследующий класс User.
    """

    def __init__(self, username, email, password, admin_level):
            super().__init__(username, email, password)
            self.admin_level = admin_level

    def get_details(self):
        return super().get_details() + f'\nУровень администратора: {self.admin_level}'

    @staticmethod
    def list_users():
        """
        Выводит список всех пользователей.
        """
        text = f'\n\nСписок пользователей:\n\n'
        for i in User.users:
            text += i.get_details() + '\n\n'
        return text

    @staticmethod
    def delete_user(username):
        """
        Удаляет пользователя по имени пользователя.
        """
        for obj in User.users:
            if hasattr(obj, 'username') and getattr(obj, 'username') == username:
                User.users.remove(obj)
                print(f'Пользователь с именем {username} найден и удален.')
                return
        print(f'Пользователь с именем {username} НЕ найден')
        return


class AuthenticationService:
    """
    Сервис для управления регистрацией и аутентификацией пользователей.
    """

    info_session = []
    def __init__(self):
        pass

    def register(self, user_class, username, email, password, *args):
        """
        Регистрация нового пользователя.
        """
        for obj in User.users:
            if hasattr(obj, 'username') and getattr(obj, 'username') == username:
                print(f'Пользователь с именем {username} уже существует!')
                return
        new_user = user_class(username, email, password, *args)
        print('Пользователь создан!')
        print(new_user.get_details())


    def login(self, username, password):
        """
        Аутентификация пользователя.
        """
        session = AuthenticationService.info_session
        session.clear()
        for user in User.users:
            if user.username == username:
                if User.check_password(user.password, password):
                    id = uuid.uuid4()
                    AuthenticationService.info_session.extend([id, user])
                    print(f'Пользователь авторизован успешно!')
                    print(AuthenticationService().get_current_user())
                    return
                else:
                    print('Не верный пароль!')
                    return
        print('Пользователь не найден!')

    def logout(self):
        """
        Выход пользователя из системы.
        """
        session = AuthenticationService.info_session
        session.clear()
        if len(session) == 2:
            print(f'Для пользователя {session[1].username} сессия завершена')
            session.clear()
        else:
            print('Авторизованных пользователей нет.')

    def get_current_user(self):
        """
        Возвращает текущего вошедшего пользователя.
        """
        session = AuthenticationService.info_session
        if len(session) == 2:
            return f'Авторизован пользователь {session[1].username}\nid: {session[0]}'
        else:
            return 'Авторизованных пользователей нет.'


print('Добавим несколько пользователей')
AuthenticationService().register(Admin, 'ad1', 'ad1@qw.er', 'passw', '2')
AuthenticationService().register(User, 'us1', 'aus1@qw.er', 'passwot')
AuthenticationService().register(Customer, 'ad1', 'cu1@qw.er', 'paerssw', 'City')
AuthenticationService().register(Admin, 'ad1', 'ad2@qw.er', 'patyssw', '4')

print('Выведим список пользователей')
print(Admin.list_users())

print('\nЗалогинимся')
AuthenticationService().login('ad1', 'passw')

print('\nЗалогинимся под другим пользователем')
AuthenticationService().login('us1', 'passwot')

print('\nЗалогинимся с не правильным паролем')
AuthenticationService().login('us1', 'pawot')

print('\nЗалогинимся под несуществующим пользователем')
AuthenticationService().login('us3', 'passwot')

print('\nразлогинимся')
AuthenticationService().logout()
print(AuthenticationService().info_session)

