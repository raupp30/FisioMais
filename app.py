from flask import Flask, render_template, request, redirect, url_for, session, flash
import firebase_admin
import pyrebase
from firebase_admin import credentials, auth, db
from werkzeug.security import generate_password_hash
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
from datetime import datetime
from functools import wraps
from flask import make_response
import requests
from utils.email_service import enviar_email_redefinicao
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred, {
    'databaseURL': os.getenv("FIREBASE_DATABASE_URL")
})

config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
    "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID"),
    "databaseURL": os.getenv("FIREBASE_DATABASE_URL")
}

API_KEY = config['apiKey']

def no_cache(view):
    def no_cache_wrapper(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    no_cache_wrapper.__name__ = view.__name__
    return no_cache_wrapper

firebase = pyrebase.initialize_app(config)
pb_auth = firebase.auth()
pb_db = firebase.database()

@app.route('/')
def home():
    return render_template('home.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa estar logado para acessar essa página.', 'warning')
            return redirect(url_for('home'))  # ou para a página de login específica
        return f(*args, **kwargs)
    return decorated_function

def tipo_usuario_required(tipo_esperado):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            token = session.get('idToken')

            if not user_id or not token:
                flash('Você precisa estar logado.', 'warning')
                return redirect(url_for('home'))

            tipo = pb_db.child("usuarios").child(user_id).child("tipo").get(token).val()

            if tipo != tipo_esperado:
                flash('Acesso negado: tipo de usuário não permitido.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacity')
def privacity():
    return render_template('privacity.html')

@app.route('/admin/painel_fisio')
@login_required
@tipo_usuario_required('fisioterapeuta')
def painel_fisio():
    return render_template('admin/painel_fisio.html')

@app.route('/admin/meus_agendamentos')
@login_required
@tipo_usuario_required('fisioterapeuta')
def meus_agendamentos_fisio():
    user_id = session.get('user_id')
    ref = db.reference('agendamentos')
    dados = ref.order_by_child('fisioterapeuta_id').equal_to(user_id).get()

    agendamentos = []
    if dados:
        for id, ag in dados.items():
            paciente_id = ag.get('paciente_id')
            
            # Buscar nome do paciente no banco de dados
            paciente_ref = db.reference(f'usuarios/{paciente_id}')
            paciente = paciente_ref.get()
            paciente_nome = paciente.get('nome') if paciente else 'Desconhecido'

            agendamentos.append({
                'id': id,
                'fisioterapeuta_nome': ag.get('fisioterapeuta_nome'),
                'data': ag.get('data'),
                'horario': ag.get('horario'),
                'paciente_id': paciente_id,
                'paciente_nome': paciente_nome
            })

    return render_template('admin/meus_agendamentos.html', agendamentos=agendamentos)

@app.route('/admin/evolucao')
@login_required
@tipo_usuario_required('fisioterapeuta')
def evolucao():
    return render_template('admin/evolucao.html')

@app.route('/register_fisio', methods=['GET', 'POST'])
def register_fisio():
    if request.method == 'POST':
        email = request.form['email']
        nome = request.form['nome']
        cpf = request.form['cpf']
        data_nasc = request.form['data_nasc']
        telefone = request.form['telefone']
        genero = request.form['genero']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        if senha != confirmar_senha:
            flash("Senhas não coincidem", "error")
            return redirect('/register_fisio')

        try:
            # ✅ Cria o usuário no Firebase Auth usando Admin SDK
            user = auth.create_user(email=email, password=senha)
            uid = user.uid

            # ✅ Salva os dados no Realtime Database via Admin SDK
            dados_fisio = {
                'email': email,
                'nome': nome,
                'cpf': cpf,
                'data_nasc': data_nasc,
                'telefone': telefone,
                'genero': genero,
                'tipo': 'fisioterapeuta'  # controle de acesso
            }

            db.reference(f'usuarios/{uid}').set(dados_fisio)

            flash("Fisioterapeuta registrado com sucesso!", "success")
            return redirect('/register_fisio')

        except Exception as e:
            flash(f"Erro ao se registrar: {e}", "error")
            return redirect('/register_fisio')

    return render_template('register_fisio.html')

@app.route("/login_fisio", methods=["GET", "POST"])
def login_fisio():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]

        try:
            user = pb_auth.sign_in_with_email_and_password(email, senha)
            uid = user["localId"]
            session['user_id'] = uid
            session['email'] = email
            session['idToken'] = user['idToken']
            return redirect("/admin/painel_fisio")

        except Exception as e:
            flash(f"Credenciais inválidas !", "danger")

    return render_template("/login_fisio.html")

def verificar_email_existente(email):
    try:
        user = auth.get_user_by_email(email)
        return True  # E-mail já está em uso
    except auth.UserNotFoundError:
        return False  # E-mail disponível

@app.route('/admin/config_fisio', methods=['GET', 'POST'])
@login_required
@tipo_usuario_required('fisioterapeuta')
def config_fisio():
    user_id = session.get('user_id')
    token = session.get('idToken')
    if not user_id or not token:
        flash("Você precisa estar logado para acessar essa página.")
        return redirect('/login_fisio')
    
    # Buscando dados do paciente no Firebase
    paciente_data = pb_db.child("usuarios").child(user_id).get(token).val()
    dados_usuario = pb_db.child("usuarios").child(user_id).get(token).val()
    
    if request.method == 'POST':
        # Aqui você pode atualizar os dados do usuário, por exemplo:
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        data_nasc = request.form['data_nasc']
        telefone = request.form['telefone']
        genero = request.form['genero']

        if email != dados_usuario['email'] and verificar_email_existente(email):
            flash("Este e-mail já está em uso por outro usuário.", "error")
            return redirect('/admin/config_fisio')

        dados_atualizados = {
            "nome": nome,
            "email": email,
            "cpf": cpf,
            "data_nasc": data_nasc,
            "telefone": telefone,
            "genero": genero,
        }
        
        pb_db.child("usuarios").child(user_id).update(dados_atualizados, token)
        flash("Dados atualizados com sucesso!", "success")
        return redirect('/admin/config_fisio')

    return render_template('admin/config_fisio.html', dados=paciente_data)

@app.route('/register_paciente', methods=['GET', 'POST'])
def register_paciente():
    if request.method == 'POST':
        email = request.form['email']
        nome = request.form['nome']
        cpf = request.form['cpf']
        data_nasc = request.form['data_nasc']
        telefone = request.form['telefone']
        genero = request.form['genero']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        if senha != confirmar_senha:
            flash("Senhas não coincidem", "error")
            return redirect('register_paciente')

        try:
            # ✅ Cria o usuário usando o Admin SDK
            user = auth.create_user(email=email, password=senha)
            uid = user.uid

            # ✅ Salva os dados no DB via Admin SDK (ignora regras)
            db.reference(f'usuarios/{uid}').set({
                'email': email,
                'nome': nome,
                'cpf': cpf,
                'data_nasc': data_nasc,
                'telefone': telefone,
                'genero': genero,
                'tipo': 'paciente'
            })

            flash("Paciente registrado com sucesso!", "success")
            return redirect('register_paciente')

        except Exception as e:
            flash(f"Erro ao registrar no Firebase: {e}", "error")

    return render_template('register_paciente.html')

@app.route("/login_paciente", methods=["GET", "POST"])
def login_paciente():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]

        try:
            user = pb_auth.sign_in_with_email_and_password(email, senha)
            uid = user["localId"]
            id_token = user['idToken']
            session['user_id'] = uid
            session['email'] = email
            session['idToken'] = id_token
            return redirect("painel_paciente")

        except Exception as e:
            flash(f"Credenciais inválidas !", "danger")

    return render_template("login_paciente.html")

@app.route('/painel_paciente')
@no_cache
@login_required
@tipo_usuario_required('paciente')
def painel_paciente():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('painel_paciente.html')

@app.route('/evolucao_paciente')
@login_required
@tipo_usuario_required('paciente')
def evolucao_paciente():
    return render_template('evolucao_paciente.html')

@app.route('/exercicios_paciente')
@login_required
@tipo_usuario_required('paciente')
def exercicios_paciente():
    return render_template('exercicios_paciente.html')

@app.route('/config_paciente', methods=['GET', 'POST'])
@login_required
@tipo_usuario_required('paciente')
def config_paciente():
    user_id = session.get('user_id')
    token = session.get('idToken')

    if not user_id or not token:
        flash("Você precisa estar logado para acessar essa página.")
        return redirect('/login_paciente')
    
    # Buscando dados do paciente no Firebase
    paciente_data = pb_db.child("usuarios").child(user_id).get(token).val()
    dados_usuario = pb_db.child("usuarios").child(user_id).get(token).val()

    if request.method == 'POST':
        # Aqui você pode atualizar os dados do usuário, por exemplo:
        nome = request.form['nome']
        email = request.form['email']
        cpf = request.form['cpf']
        data_nasc = request.form['data_nasc']
        telefone = request.form['telefone']
        genero = request.form['genero']

        if email != dados_usuario['email'] and verificar_email_existente(email):
            flash("Este e-mail já está em uso por outro usuário.", "error")
            return redirect('/admin/config_paciente')

        dados_atualizados = {
            "nome": nome,
            "email": email,
            "cpf": cpf,
            "data_nasc": data_nasc,
            "telefone": telefone,
            "genero": genero,
        }
        
        pb_db.child("usuarios").child(user_id).update(dados_atualizados, token)
        flash("Dados atualizados com sucesso!", "success")
        return redirect('/config_paciente')

    return render_template('config_paciente.html', dados=paciente_data)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logout realizado com sucesso!", "success")
    return redirect('/')

@app.route('/agendar', methods=['GET', 'POST'])
def agendar():
    if request.method == 'POST':
        fisioterapeuta = request.form['fisioterapeuta']
        data = request.form['data-agendamento']
        horario = request.form['horario']
        fisioterapeuta_id = request.form['fisioterapeuta']
    # Pega o nome do fisioterapeuta para salvar junto (busca no DB)
        usuario_ref = db.reference(f'usuarios/{fisioterapeuta_id}')
        fisioterapeuta_nome = usuario_ref.child('nome').get()
        ref = db.reference('agendamentos')
        ref.push({
    'fisioterapeuta_id': fisioterapeuta_id,
    'fisioterapeuta_nome': fisioterapeuta_nome,
    'data': data,
    'horario': horario,
    'paciente_id': session.get('user_id'),
    # opcional, pega nome do paciente também
})

        return redirect(url_for('meus_agendamentos_paciente'))

    # Buscar fisioterapeutas cadastrados
    usuarios_ref = db.reference('usuarios')
    usuarios = usuarios_ref.get()

    fisioterapeutas = []
    if usuarios:
        for uid, dados in usuarios.items():
            if dados.get('tipo') == 'fisioterapeuta':
                fisioterapeutas.append({
                    'id': uid,
                    'nome': dados.get('nome')
                })

    return render_template('agendar.html', fisioterapeutas=fisioterapeutas)

@app.route('/excluir/<id>')
def excluir_agendamento(id):
    db.reference(f'agendamentos/{id}').delete()
    return redirect(url_for('meus_agendamentos_paciente'))

@app.route('/editar/<id>', methods=['GET', 'POST'])
def editar_agendamento(id):
    ref = db.reference(f'agendamentos/{id}')

    # Referência para fisioterapeutas cadastrados
    fisios_ref = db.reference('usuarios')
    fisioterapeutas = fisios_ref.order_by_child('tipo').equal_to('fisioterapeuta').get()

    if request.method == 'POST':
        fisioterapeuta_id = request.form['fisioterapeuta']
        ref.update({
            'fisioterapeuta': fisioterapeuta_id,
            'data': request.form['data-agendamento'],
            'horario': request.form['horario']
        })
        return redirect(url_for('meus_agendamentos_paciente'))

    dados = ref.get()
    return render_template('editar.html', id=id, agendamento=dados, fisioterapeutas=fisioterapeutas)


@app.route('/meus_agendamentos_paciente')
@login_required
@tipo_usuario_required('paciente')
def meus_agendamentos_paciente():
    user_id = session.get('user_id')  # ID do paciente logado

    # Referência ao banco
    ref = db.reference('agendamentos')

    try:
        # Busca todos os agendamentos
        dados = ref.order_by_child('paciente_id').equal_to(user_id).get()

        agendamentos = []
        if dados:
            for id, ag in dados.items():
                agendamentos.append({
                    'id': id,
                    'fisioterapeuta_nome': ag.get('fisioterapeuta_nome'),
                    'data': ag.get('data'),
                    'horario': ag.get('horario'),
                })

        return render_template('meus_agendamentos_paciente.html', agendamentos=agendamentos)
    
    except Exception as e:
        print(f"Erro ao buscar agendamentos: {e}")
        return "Erro ao buscar seus agendamentos", 500

@app.route('/redefinir_senha', methods=['GET', 'POST'])
def redefinir_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Por favor, informe um e-mail válido.', 'danger')
            return redirect(url_for('redefinir_senha'))

        resposta = enviar_email_redefinicao(email, API_KEY)
        if 'error' in resposta:
            erro = resposta['error'].get('message', 'Erro desconhecido')
            flash(f'Erro ao enviar e-mail: {erro}', 'danger')
            return redirect(url_for('redefinir_senha'))
        else:
            flash('E-mail de redefinição de senha enviado com sucesso!', 'success')
            return redirect(url_for('home'))  # ou outra página que você queira

    return render_template('redefinir_senha.html')
if __name__ == '__main__':
    app.run(debug=True)

