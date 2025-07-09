from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'chave-secreta-teste'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # rota para login quando precisar

# "Banco" fake de usuários
users = {
    'user1': {'id': 'user1', 'password': '1234'},
    'user2': {'id': 'user2', 'password': 'abcd'}
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return f'Olá, {current_user.id}! <a href="/logout">Sair</a>'
    else:
        return 'Você não está logado. <a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        id = request.form['username']
        password = request.form['password']

        user = users.get(id)
        if user and user['password'] == password:
            user_obj = User(id)
            login_user(user_obj)
            flash('Logado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas', 'danger')

    return '''
        <h2>Login</h2>
        <form method="post">
            Usuário: <input type="text" name="username"><br>
            Senha: <input type="password" name="password"><br>
            <input type="submit" value="Entrar">
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sessão.', 'info')
    return redirect(url_for('index'))

@app.route('/protegida')
@login_required
def protegida():
    return f'Essa é uma página protegida! Usuário: {current_user.id}'

if __name__ == '__main__':
    app.run(debug=True)
