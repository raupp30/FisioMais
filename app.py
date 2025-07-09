from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, json
import pyrebase, firebase_admin
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

# EXCLUSIVO LOCAL #
#cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
#cred = credentials.Certificate(cred_path)

# EXCLUSIVO DEPLOYS #
cred_dict = json.loads(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON"))
cred = credentials.Certificate(cred_dict)
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
    @wraps(view)
    def no_cache_wrapper(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return no_cache_wrapper


firebase = pyrebase.initialize_app(config)
pb_auth = firebase.auth()
pb_db = firebase.database()

@app.route('/')
def home():
    return render_template('home.html')

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Você precisa estar logado para acessar esta página.", "warning")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapper

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
@no_cache
def painel_fisio():
    return render_template('admin/painel_fisio.html')

@app.route('/admin/meus_agendamentos')
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def meus_agendamentos_fisio():
    user_id = session.get('user_id')
    ref = db.reference('agendamentos')
    dados = ref.order_by_child('fisioterapeuta_id').equal_to(user_id).get()

    agendamentos = []
    if dados:
        for id, ag in dados.items():
            paciente_id = ag.get('paciente_id')
            paciente_ref = db.reference(f'usuarios/{paciente_id}')
            paciente = paciente_ref.get()
            paciente_nome = paciente.get('nome') if paciente else 'Desconhecido'

            agendamentos.append({
                'id': id,
                'fisioterapeuta_nome': ag.get('fisioterapeuta_nome'),
                'data': ag.get('data'),
                'horario': ag.get('horario'),
                'paciente_id': paciente_id,
                'paciente_nome': paciente_nome,
                'status': ag.get('status', 'pendente'),
                'observacoes': ag.get('observacoes', '')
            })

    filtro = request.args.get('filtro', '').lower()
    if filtro:
        def contem_texto(ag):
            return (
                filtro in str(ag.get('paciente_nome', '')).lower() or
                filtro in str(ag.get('data', '')).lower() or
                filtro in str(ag.get('horario', '')).lower() or
                filtro in str(ag.get('observacoes', '')).lower() or
                filtro in str(ag.get('status', '')).lower()
            )
        agendamentos = list(filter(contem_texto, agendamentos))
    agendamentos.sort(
    key=lambda x: (
        0 if x.get('status', '').lower() == 'pendente' else 1,  # pendente vem antes
        datetime.strptime(f"{x['data']} {x['horario']}", "%Y-%m-%d %H:%M")
    ),
    reverse=False
)
    return render_template('admin/meus_agendamentos.html', agendamentos=agendamentos)

@app.route('/admin/atualizar_agendamento/<id>', methods=['POST'])
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def atualizar_agendamento(id):
    acao = request.form.get('acao')
    observacoes = request.form.get('observacoes')

    ref = db.reference(f'agendamentos/{id}')
    
    updates = {
        'observacoes': observacoes
    }

    if acao == 'finalizar':
        updates['finalizado'] = True

    try:
        ref.update(updates)
        flash('Agendamento atualizado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao atualizar agendamento: {e}', 'danger')

    return redirect(url_for('meus_agendamentos_fisio'))

@app.route('/finalizar_agendamento/<string:id>', methods=['POST'])
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def finalizar_agendamento(id):
    observacoes = request.form.get('observacoes', '').strip()
    ref = db.reference(f'agendamentos/{id}')
    if ref.get():
        ref.update({
            'status': 'finalizado',
            'observacoes': observacoes
        })
    return redirect(url_for('meus_agendamentos_fisio'))

@app.route('/admin/evolucao')
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def evolucao():
    user_id = session.get('user_id')

    agendamentos_ref = db.reference('agendamentos')
    dados = agendamentos_ref.order_by_child('fisioterapeuta_id').equal_to(user_id).get()

    evolucoes = []
    if dados:
        for id, ag in dados.items():
            if ag.get('status') == 'finalizado':
                paciente_id = ag.get('paciente_id')
                paciente_nome = db.reference(f'usuarios/{paciente_id}/nome').get() or 'Desconhecido'

                evolucoes.append({
                    'id': id,
                    'data': ag.get('data'),
                    'horario': ag.get('horario'),
                    'paciente_id': paciente_id,
                    'paciente_nome': paciente_nome,
                    'observacoes': ag.get('observacoes'),
                })

    filtro = request.args.get('filtro', '').lower()
    if filtro:
        def contem_texto(evo):
            return (
                filtro in str(evo.get('paciente_nome', '')).lower() or
                filtro in str(evo.get('data', '')).lower() or
                filtro in str(evo.get('horario', '')).lower() or
                filtro in str(evo.get('observacoes', '')).lower()
            )
        evolucoes = list(filter(contem_texto, evolucoes))

    evolucoes.sort(
    key=lambda x: datetime.strptime(f"{x['data']} {x['horario']}", "%Y-%m-%d %H:%M"),
    reverse=True
)
    return render_template('admin/evolucao.html', evolucoes=evolucoes)
from datetime import datetime, date

@app.route('/admin/evolucao/editar_obs/<agendamento_id>', methods=['GET', 'POST'], endpoint='editar_obs_evolucao')
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def editar_observacoes(agendamento_id):
    ag_ref = db.reference(f'agendamentos/{agendamento_id}')
    agendamento = ag_ref.get()

    if not agendamento or agendamento.get('status') != 'finalizado':
        flash('Agendamento não encontrado ou não finalizado.', 'danger')
        return redirect(url_for('evolucao'))

    if request.method == 'POST':
        novas_obs = request.form.get('observacoes', '').strip()

        ag_ref.update({
            'observacoes': novas_obs
        })

        flash('Observações atualizadas com sucesso!', 'success')
        return redirect(url_for('evolucao'))

    return render_template('admin/editar_observacoes.html', agendamento=agendamento, agendamento_id=agendamento_id)

@app.route('/register_fisio', methods=['GET', 'POST'])
def register_fisio():
    if request.method == 'POST':
        email = request.form['email']
        nome = request.form['nome']
        cpf = request.form['cpf']
        data_nasc_str = request.form['data_nasc']
        telefone = request.form['telefone']
        genero = request.form['genero']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        if senha != confirmar_senha:
            flash("Senhas não coincidem", "error")
            return redirect('/register_fisio')

        # validar idade
        try:
            data_nasc = datetime.strptime(data_nasc_str, '%Y-%m-%d').date()
            hoje = date.today()
            idade = hoje.year - data_nasc.year - ((hoje.month, hoje.day) < (data_nasc.month, data_nasc.day))

            if idade < 22:
                flash("Você deve ter pelo menos 22 anos para se registrar como fisioterapeuta.", "error")
                return redirect('/register_fisio')
        except ValueError:
            flash("Data de nascimento inválida.", "error")
            return redirect('/register_fisio')

        try:
            # cria usuario firebase usando Admin SDK
            user = auth.create_user(email=email, password=senha)
            uid = user.uid

            # salva dados no firebase usando Admin SDK
            dados_fisio = {
                'email': email,
                'nome': nome,
                'cpf': cpf,
                'data_nasc': data_nasc_str,
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
        return True  # email em uso
    except auth.UserNotFoundError:
        return False  # email disp

@app.route('/admin/config_fisio', methods=['GET', 'POST'])
@login_required
@no_cache
@tipo_usuario_required('fisioterapeuta')
def config_fisio():
    user_id = session.get('user_id')
    token = session.get('idToken')
    if not user_id or not token:
        flash("Você precisa estar logado para acessar essa página.")
        return redirect('/login_fisio')
    
    paciente_data = pb_db.child("usuarios").child(user_id).get(token).val()
    dados_usuario = pb_db.child("usuarios").child(user_id).get(token).val()
    
    if request.method == 'POST':
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
            user = auth.create_user(email=email, password=senha)
            uid = user.uid

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
    user_id = session.get('user_id')

    agendamentos_ref = db.reference('agendamentos')
    dados = agendamentos_ref.order_by_child('paciente_id').equal_to(user_id).get()

    evolucoes = []
    if dados:
        for id, ag in dados.items():
            if ag.get('status', '').lower() == 'finalizado':
                fisio_id = ag.get('fisioterapeuta_id')
                fisio_nome = 'Desconhecido'

                if fisio_id:
                    fisio_nome = db.reference(f'usuarios/{fisio_id}/nome').get() or 'Desconhecido'

                evolucoes.append({
                    'id': id,
                    'fisioterapeuta': fisio_nome,
                    'data': ag.get('data'),
                    'horario': ag.get('horario'),
                    'observacoes': ag.get('observacoes', '')
                })

    filtro = request.args.get('filtro', '').lower()
    if filtro:
        evolucoes = [
            evo for evo in evolucoes if
            filtro in evo['fisioterapeuta'].lower() or
            filtro in evo['data'].lower() or
            filtro in evo['horario'].lower() or
            filtro in evo['observacoes'].lower()
        ]

    # ordenar por data  /hora decrescente
    evolucoes.sort(
        key=lambda x: datetime.strptime(f"{x['data']} {x['horario']}", "%Y-%m-%d %H:%M"),
        reverse=True
    )

    return render_template('evolucao_paciente.html', evolucoes=evolucoes)

@app.route('/exercicios_paciente')
@login_required
@no_cache
@tipo_usuario_required('paciente')
def exercicios_paciente():
    return render_template('exercicios_paciente.html')

@app.route('/config_paciente', methods=['GET', 'POST'])
@login_required
@no_cache
@tipo_usuario_required('paciente')
def config_paciente():
    user_id = session.get('user_id')
    token = session.get('idToken')

    if not user_id or not token:
        flash("Você precisa estar logado para acessar essa página.")
        return redirect('/login_paciente')
    
    paciente_data = pb_db.child("usuarios").child(user_id).get(token).val()
    dados_usuario = pb_db.child("usuarios").child(user_id).get(token).val()

    if request.method == 'POST':
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
@login_required
@no_cache
def logout():
    session.clear()
    flash("Logout realizado com sucesso!", "success")
    return redirect('/')

@app.route('/horarios_disponiveis')
@login_required
@no_cache
def horarios_disponiveis():
    data = request.args.get('data')
    fisio_id = request.args.get('fisioterapeuta_id')

    if not data or not fisio_id:
        return jsonify([])

    # gerar horários valido: 07:00 - 19:00, exceto 12:00
    horarios_base = [f"{h:02d}:00" for h in range(7, 19) if h != 12]

    # vrrificar ocupação no Firebase
    ref = db.reference(f'horarios_disponiveis/{fisio_id}/{data}')
    ocupados = ref.get() or {}

    horarios_disponiveis = []
    for horario in horarios_base:
        if ocupados.get(horario) != 'ocupado':
            horarios_disponiveis.append({
                'valor': horario,
                'label': f"{horario} - {int(horario[:2]) + 1:02d}:00 (1 vaga restante)"
            })

    return jsonify(horarios_disponiveis)


@app.route('/agendar', methods=['GET', 'POST'])
@login_required
@no_cache
@tipo_usuario_required('paciente')
def agendar():
    usuarios_ref = db.reference('usuarios')
    todos_usuarios = usuarios_ref.get()

    fisioterapeutas = []
    if todos_usuarios:
        for id, user in todos_usuarios.items():
            if user.get('tipo') == 'fisioterapeuta':
                fisioterapeutas.append({'id': id, 'nome': user.get('nome')})

    if request.method == 'POST':
        fisioterapeuta_id = request.form['fisioterapeuta']
        data = request.form['data-agendamento']
        horario = request.form['horario']

        # verificar se horário está ocupado
        horario_ref = db.reference(f'horarios_disponiveis/{fisioterapeuta_id}/{data}/{horario}')
        estado = horario_ref.get()
        if estado == 'ocupado':
            flash('⛔ Este horário já foi agendado. Por favor, escolha outro.', 'erro')
            return render_template('agendar.html', fisioterapeutas=fisioterapeutas)

        #  nome do fisioterapeuta
        fisioterapeuta_nome = usuarios_ref.child(fisioterapeuta_id).child('nome').get()

        # save
        db.reference('agendamentos').push({
            'fisioterapeuta_id': fisioterapeuta_id,
            'fisioterapeuta_nome': fisioterapeuta_nome,
            'data': data,
            'horario': horario,
            'paciente_id': session.get('user_id'),
            'status': 'pendente',
            'observacoes': ''
        })

        # att o horário como ocupado
        horario_ref.set('ocupado')

        return redirect(url_for('meus_agendamentos_paciente'))

    return render_template('agendar.html', fisioterapeutas=fisioterapeutas, current_date=date.today())

@app.route('/excluir/<id>')
@login_required
@no_cache
@tipo_usuario_required('paciente')
def excluir_agendamento(id):
    ref = db.reference(f'agendamentos/{id}')
    agendamento = ref.get()
    if not agendamento or agendamento.get('paciente_id') != session.get('user_id'):
        flash("Agendamento não encontrado ou sem permissão.", "erro")
        return redirect(url_for('meus_agendamentos_paciente'))

    # libera horário ocupado
    fisioterapeuta_id = agendamento.get('fisioterapeuta_id')
    data = agendamento.get('data')
    horario = agendamento.get('horario')
    horario_ref = db.reference(f'horarios_disponiveis/{fisioterapeuta_id}/{data}/{horario}')
    horario_ref.delete()

    # exclui agendamento
    ref.delete()
    flash("Agendamento excluído com sucesso!", "sucesso")
    return redirect(url_for('meus_agendamentos_paciente'))


@app.route('/editar/<id>', methods=['GET', 'POST'])
@login_required
@no_cache
@tipo_usuario_required('paciente')
def editar_agendamento(id):
    paciente_id = session.get('user_id')
    ref = db.reference(f'agendamentos/{id}')
    agendamento = ref.get()

    if not agendamento or agendamento.get('paciente_id') != paciente_id:
        flash("Agendamento não encontrado ou sem permissão.", "erro")
        return redirect(url_for('meus_agendamentos_paciente'))

    fisios_ref = db.reference('usuarios')
    fisioterapeutas = fisios_ref.order_by_child('tipo').equal_to('fisioterapeuta').get() or {}

    if request.method == 'POST':
        novo_fisio_id = request.form['fisioterapeuta']
        nova_data = request.form['data-agendamento']
        novo_horario = request.form['horario']

        # se não mudou nada redireciona
        if (novo_fisio_id == agendamento.get('fisioterapeuta_id') and
            nova_data == agendamento.get('data') and
            novo_horario == agendamento.get('horario')):
            flash("Nenhuma alteração feita.", "info")
            return redirect(url_for('meus_agendamentos_paciente'))

        # verificar disponibilidade do novo horário
        horario_ref = db.reference(f'horarios_disponiveis/{novo_fisio_id}/{nova_data}/{novo_horario}')
        estado = horario_ref.get()
        if estado == 'ocupado':
            flash("⛔ Horário já está ocupado. Por favor, escolha outro.", "erro")
            return render_template('editar.html', id=id, agendamento=agendamento, fisioterapeutas=fisioterapeutas)

        # liberar horário velho
        horario_antigo_ref = db.reference(f'horarios_disponiveis/{agendamento.get("fisioterapeuta_id")}/{agendamento.get("data")}/{agendamento.get("horario")}')
        horario_antigo_ref.delete()

        # marcar o novo horário como ocupado
        horario_ref.set('ocupado')

        # att
        fisioterapeuta_nome = fisios_ref.child(novo_fisio_id).child('nome').get()
        ref.update({
            'fisioterapeuta_id': novo_fisio_id,
            'fisioterapeuta_nome': fisioterapeuta_nome,
            'data': nova_data,
            'horario': novo_horario
        })

        flash("Agendamento editado com sucesso!", "sucesso")
        return redirect(url_for('meus_agendamentos_paciente'))

    return render_template('editar.html', id=id, agendamento=agendamento, fisioterapeutas=fisioterapeutas)

@app.route('/meus_agendamentos_paciente')
@login_required
@no_cache
@tipo_usuario_required('paciente')
def meus_agendamentos_paciente():
    user_id = session.get('user_id')  # id pacient

    # ref ao banco
    ref = db.reference('agendamentos')

    try:
        # buscar todos os agendamentos do paciente
        dados = ref.order_by_child('paciente_id').equal_to(user_id).get()

        agendamentos = []
        if dados:
            for id, ag in dados.items():
                # ignora se for finalizado
                if ag.get('status', '').lower() == 'finalizado':
                    continue

                agendamentos.append({
                    'id': id,
                    'fisioterapeuta_nome': ag.get('fisioterapeuta_nome'),
                    'data': ag.get('data'),
                    'horario': ag.get('horario'),
                    'status': ag.get('status', 'pendente')
                })

        agendamentos.sort(
            key=lambda x: (
                0 if x.get('status', '').lower() == 'pendente' else 1,
                datetime.strptime(f"{x['data']} {x['horario']}", "%Y-%m-%d %H:%M")
            ),
            reverse=False
        )

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
            return redirect(url_for('redefinir_senha')) 

    return render_template('redefinir_senha.html')

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d/%m/%Y'):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return value
    return value.strftime(format)

if __name__ == '__main__':
    app.run(debug=True)

