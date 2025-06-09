import tkinter as tk
import sqlite3
import re
from tkinter import messagebox
from tkinter import ttk

class Aplicacao:
    def __init__(self):
        self.janela = tk.Tk()
        self.janela.title("Sistema de Autenticação")
        self.janela.geometry("600x620")
        self.janela.configure(bg="#f0f0f0")
        
        self.conectar_banco()

        self.criar_tela_inicial()
        self.janela.mainloop()

    def conectar_banco(self):
        try:
            self.conn = sqlite3.connect('Empresa.db') 
            self.cursor = self.conn.cursor()

            # Criar tabela Setor se não existir
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Setor (
                Nome_Setor TEXT PRIMARY KEY,
                Func TEXT
            )
            ''')

            # Criar tabela Funcionarios se não existir
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Funcionarios (
                CPF TEXT PRIMARY KEY,
                Nome TEXT NOT NULL,
                Email TEXT UNIQUE NOT NULL,
                Senha TEXT NOT NULL,
                Nome_Setor TEXT,
                FOREIGN KEY (Nome_Setor) REFERENCES Setor(Nome_Setor)
            )
            ''')
            self.cursor.execute
            self.conn.commit()
            print("Conexão com banco de dados estabelecida com sucesso!")
        except sqlite3.Error as e:
            messagebox.showerror("ERROR", f"Erro ao tentar conectar-se com o banco de dados: {e}")

    def criar_tela_inicial(self):
        for widget in self.janela.winfo_children():
            widget.destroy()
        
        # Frame principal
        self.frame = tk.Frame(self.janela, bg="#fff", bd=2, relief="groove")
        self.frame.place(relx=0.5, rely=0.5, anchor="center", width=400, height=300)
        
        # Título
        tk.Label(self.frame, text="Bem-vindo", font=("Arial", 24, "bold"), bg="#fff").pack(pady=30)
        
        # Botão de Login
        tk.Button(self.frame, text="Login", font=("Arial", 12), bg="#4CAF50", fg="white",
                 command=self.mostrar_login, width=20).pack(pady=10)
        
        # Botão de Registro
        tk.Button(self.frame, text="Registrar", font=("Arial", 12), bg="#2196F3", fg="white",
                 command=self.mostrar_registro, width=20).pack(pady=10)
    
    def mostrar_login(self):
        for widget in self.janela.winfo_children():
            widget.destroy()
        
        Login(self.janela, self)
    
    def mostrar_registro(self):
        for widget in self.janela.winfo_children():
            widget.destroy()
        
        Registrar(self.janela, self)


class Registrar:
    def __init__(self, janela_principal, app):
        self.janela = janela_principal
        self.app = app
        self.mostrar = False
        
        self.criar_widgets()
    
    def criar_widgets(self):
        # Frame principal
        self.frame = tk.Frame(self.janela, bg="#fff", bd=2, relief="groove")
        self.frame.place(relx=0.5, rely=0.5, anchor="center", width=600, height=620)
        
        # Título
        tk.Label(self.frame, text="Registrar", font=("Arial", 24, "bold"), bg="#fff").pack(pady=15)

        # CPF
        tk.Label(self.frame, text="CPF", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.cpf_frame = tk.Frame(self.frame, bg="#fff")
        self.cpf_frame.pack(pady=5)
        
        self.entrada_cpf = tk.Entry(self.cpf_frame, 
                                  font=("Arial", 10), 
                                  bd=1, 
                                  relief="solid", 
                                  width=30)
        self.entrada_cpf.pack(pady=5, ipadx=10, ipady=5)
        self.entrada_cpf.bind("<KeyRelease>", self.formatar_cpf)

        # Nome
        tk.Label(self.frame, text="Nome", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.nome_frame = tk.Frame(self.frame, bg="#fff")
        self.nome_frame.pack(pady=5)
        
        self.entrada_nome = tk.Entry(self.nome_frame, 
                                    font=("Arial", 10), 
                                    bd=1, relief="solid", 
                                    width=30)
        self.entrada_nome.pack(pady=5, ipadx=10, ipady=5)
       
        # Email
        tk.Label(self.frame, text="Email", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.email_frame = tk.Frame(self.frame, bg="#fff")
        self.email_frame.pack(pady=5)
        
        self.entrada_email = tk.Entry(self.email_frame, 
                                    font=("Arial", 10), 
                                    bd=1, relief="solid", 
                                    width=30)
        self.entrada_email.pack(pady=5, ipadx=10, ipady=5)
        self.entrada_email.bind("<KeyRelease>", self.validar_email_tempo_real)

        # Senha
        tk.Label(self.frame, text="Senha", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.senha_frame = tk.Frame(self.frame, bg="#fff")
        self.senha_frame.pack(pady=5)
        
        self.entrada_senha = tk.Entry(self.senha_frame, 
                                    font=("Arial", 10), 
                                    bd=1,
                                    relief="solid", 
                                    show="•", 
                                    width=30)
        self.entrada_senha.pack(pady=5, ipadx=10, ipady=5)

        # Confirmar Senha
        tk.Label(self.frame, text="Confirmar Senha", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.confirmar_senha_frame = tk.Frame(self.frame, bg="#fff")
        self.confirmar_senha_frame.pack(pady=5)
        
        self.entrada_confirmar_senha = tk.Entry(self.confirmar_senha_frame, 
                                              font=("Arial", 10),
                                              bd=1, relief="solid", 
                                              show="•", 
                                              width=30)
        self.entrada_confirmar_senha.pack(pady=5, ipadx=10, ipady=5)
        
        # Botão de Registro
        tk.Button(self.frame, text="Registrar", font=("Arial", 15, "bold"), 
                bg="#4CAF50", fg="white", activebackground="#45a049", 
                width=15, command=self.validar_registro).pack(pady=15)
        
        # Botão para voltar
        tk.Button(self.frame, text="Voltar", font=("Arial", 13, "bold"), 
                width=12, command=self.app.criar_tela_inicial).pack(pady=10)

    def formatar_cpf(self, event):
        cpf = self.entrada_cpf.get()
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) > 11:
            cpf = cpf[:11]

        cpf_formatado = ""
        for i in range(len(cpf)):
            if i in [3, 6]:
                cpf_formatado += "."
            elif i == 9:
                cpf_formatado += "-"
            cpf_formatado += cpf[i]
        
        self.entrada_cpf.delete(0, tk.END)
        self.entrada_cpf.insert(0, cpf_formatado)
    
    def validar_cpf(self):
        cpf = self.entrada_cpf.get()
        cpf = re.sub(r'[^0-9]', '', cpf)
    
        if len(cpf) != 11:
            return False
    
        # Verifica se todos os dígitos são iguais
        if cpf == cpf[0] * 11:
            return False
    
        # Cálculo do primeiro dígito verificador
        soma = 0
        for i in range(9):
            soma += int(cpf[i]) * (10 - i)
            resto = (soma * 10) % 11
            digito1 = resto if resto < 10 else 0
    
        if str(digito1) != cpf[9]:
            return False
    
        # Cálculo do segundo dígito verificador
        soma = 0
        for i in range(10):
            soma += int(cpf[i]) * (11 - i)
            resto = (soma * 10) % 11
            digito2 = resto if resto < 10 else 0
    
        if str(digito2) != cpf[10]:
            return False
    
        return True
    
    def validar_email(self, email):
        padrao = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(padrao, email) is not None
    
    def validar_email_tempo_real(self, event=None):
        email = self.entrada_email.get()
        if email:
            if not self.validar_email(email):
                self.entrada_email.config(bg="#ffdddd")
                return False
            else:
                self.entrada_email.config(bg="#fff")
                return True
        return False
    
    def validar_senha(self):
        senha = self.entrada_senha.get()
        confirmar_senha = self.entrada_confirmar_senha.get()
        
        if not senha or not confirmar_senha:
            self.entrada_senha.config(bg="#ffdddd")
            self.entrada_confirmar_senha.config(bg="#ffdddd")
            return False, "Preencha ambos os campos de senha"
        
        if senha != confirmar_senha:
            self.entrada_senha.config(bg="#ffdddd")
            self.entrada_confirmar_senha.config(bg="#ffdddd")
            return False, "As senhas não coincidem"
        
        if len(senha) < 8:
            self.entrada_senha.config(bg="#ffdddd")
            self.entrada_confirmar_senha.config(bg="#ffdddd")
            return False, "A senha deve ter pelo menos 8 caracteres"
        
        return True, ""
    
    def validar_registro(self):

        cpf = re.sub(r'[^0-9]', '', self.entrada_cpf.get())
        nome = self.entrada_nome.get()
        email = self.entrada_email.get()
        senha = self.entrada_senha.get()
        confirmar_senha = self.entrada_confirmar_senha.get()

        # Validar nome
        if not nome:
            messagebox.showerror("Erro", "Nome é obrigatório!")
            return

        # Validar email
        if not email:
            messagebox.showerror("Erro", "Email é obrigatório!")
            return
        
        if not self.validar_email(email):
            messagebox.showerror("Erro", "Email inválido! Use o formato exemplo@dominio.com")
            return

        # Validar senha
        if not senha or not confirmar_senha:
            messagebox.showerror("Erro", "Preencha ambos os campos de senha!")
            return
        
        if senha != confirmar_senha:
            messagebox.showerror("Erro", "As senhas não coincidem!")
            return
        
        if len(senha) < 8:
            messagebox.showerror("Erro", "A senha deve ter pelo menos 8 caracteres!")
            return

        # Se todas as validações passarem, prosseguir com o registro
        self.completar_registro(cpf, nome, email, senha)

    def completar_registro(self, cpf, nome, email, senha):
        # Campo de seleção de setor
        tk.Label(self.frame, text="Setor", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.setor_frame = tk.Frame(self.frame, bg="#fff")
        self.setor_frame.pack(pady=5)

        # Obter setores existentes no banco de dados
        try:
            self.app.cursor.execute("SELECT Nome_Setor FROM Setor")
            setores = [row[0] for row in self.app.cursor.fetchall()]
        except sqlite3.Error as e:
            messagebox.showerror("ERROR", f"Erro ao carregar setores: {e}")
            setores = []

        if not setores:
            try:
                self.app.cursor.execute("INSERT INTO Setor (Nome_Setor, Func) VALUES (?, ?)", 
                                    ("Administrativo", "Gerente"))
                self.app.conn.commit()
                setores = ["Administrativo"]
            except sqlite3.Error as e:
                messagebox.showerror("ERROR", f"Erro ao criar setor padrão: {e}")

        self.var_setor = tk.StringVar(self.setor_frame)
        self.var_setor.set(setores[0] if setores else "")
        self.entrada_setor = tk.OptionMenu(self.setor_frame, self.var_setor, *setores)
        self.entrada_setor.pack(pady=5, ipadx=10, ipady=5)

        setor = self.var_setor.get()

        try:
            self.cursor = self.app.conn.cursor()
        
            # Verificar se CPF já existe
            self.cursor.execute("SELECT 1 FROM Funcionarios WHERE CPF = ?", (cpf,))
            if self.cursor.fetchone():
                messagebox.showerror("ERROR", "CPF já cadastrado!")
                return

            # Verificar se email já existe
            self.cursor.execute("SELECT 1 FROM Funcionarios WHERE Email = ?", (email,))
            if self.cursor.fetchone():
                messagebox.showerror("ERROR", "Email já cadastrado!")
                return
        
            # Inserir novo usuário
            self.cursor.execute(
                "INSERT INTO Funcionarios (CPF, Nome, Email, Senha, Nome_Setor) VALUES (?, ?, ?, ?, ?)",
                (cpf, nome, email, senha, setor)
            )
            self.app.conn.commit()

            messagebox.showinfo("Sucesso", "Registro realizado com sucesso!")
            self.app.criar_tela_inicial()

        except sqlite3.Error as e:
            messagebox.showerror("ERROR", f"Erro ao registrar usuario: {e}")
        

class Login:
    def __init__(self, janela_principal, app):
        self.janela = janela_principal
        self.app = app
        self.mostrar = False
        
        self.criar_widgets()
    
    def criar_widgets(self):
        # Frame principal
        self.frame = tk.Frame(self.janela, bg="#fff", bd=2, relief="groove")
        self.frame.place(relx=0.5, rely=0.5, anchor="center", width=600, height=620)
        
        # Título
        tk.Label(self.frame, text="Login", font=("Arial", 24, "bold"), bg="#fff").pack(pady=15)
        
        # Usuário (CPF)
        tk.Label(self.frame, text="CPF", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        
        self.entrada_usuario = tk.Entry(
            self.frame,
            font=("Arial", 10),
            bd=1,
            relief="solid",
            width=30,
        )
        self.entrada_usuario.pack(pady=5, ipadx=10, ipady=5)
        self.entrada_usuario.bind("<KeyRelease>", self.formatar_cpf)

        # Senha
        tk.Label(self.frame, text="Senha", font=("Arial", 10, "bold"), bg="#fff").pack(pady=5)
        self.senha_frame = tk.Frame(self.frame, bg="#fff")
        self.senha_frame.pack(pady=5)
        
        self.entrada_senha = tk.Entry(self.senha_frame, 
                                    font=("Arial", 10), 
                                    bd=1, relief="solid", 
                                    show="•", 
                                    width=30)
        self.entrada_senha.pack(pady=5, ipadx=10, ipady=5)
        
        # Botão de Login
        tk.Button(self.frame, text="Entrar", font=("Arial", 15, "bold"), 
                bg="#4CAF50", fg="white", activebackground="#45a049", 
                width=15, command=self.fazer_login).pack(pady=15)
        
        # Botão para voltar
        tk.Button(self.frame, text="Voltar", font=("Arial", 13, "bold"), 
                  width=12, command=self.app.criar_tela_inicial).pack(pady=10)
    
    def formatar_cpf(self, event):
        cpf = self.entrada_usuario.get()
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) > 11:
            cpf = cpf[:11]

        cpf_formatado = ""
        for i in range(len(cpf)):
            if i in [3, 6]:
                cpf_formatado += "."
            elif i == 9:
                cpf_formatado += "-"
            cpf_formatado += cpf[i]
        
        self.entrada_usuario.delete(0, tk.END)
        self.entrada_usuario.insert(0, cpf_formatado)
    
    def validar_cpf(self):
        cpf = self.entrada_usuario.get()
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) != 11:
            return False
        
        if cpf == cpf[0] * 11:
            return False
        
        for i in range(9, 11):
            soma = sum(int(cpf[num]) * ((i+1) - num) for num in range(0, i))
            digito = (soma * 10) % 11
            digito = digito if digito < 10 else 0
            if str(digito) != cpf[i]:
                return False
        
        return True
    
    def fazer_login(self):
        usuario = self.entrada_usuario.get()
        senha = self.entrada_senha.get()
    
        if not usuario or not senha:
            messagebox.showinfo("Erro", "Por favor, preencha todos os campos!")
            return
        
        if not self.validar_cpf():
            self.entrada_usuario.config(bg="#ffdddd")
            messagebox.showerror("ERROR", "CPF inválido!")
            return
        else:
            self.entrada_usuario.config(bg="#fff")
        
        if len(senha) < 8:
            self.entrada_senha.config(bg="#ffdddd")
            messagebox.showerror("ERROR", "Senha inválida!")
            return
        else:
            self.entrada_senha.config(bg="#fff")

        # Verificar credenciais no banco de dados
        cpf = re.sub(r'[^0-9]', '', usuario)
        try:
            self.app.cursor.execute('''
                SELECT f.Nome, f.Nome_Setor, s.Func 
                FROM Funcionarios f
                JOIN Setor s ON f.Nome_Setor = s.Nome_Setor
                WHERE f.CPF = ? AND f.Senha = ?
            ''', (cpf, senha))
            resultado = self.app.cursor.fetchone()
            
            if resultado:
                # Mostrar tela de CRUD em vez da mensagem de sucesso
                TelaCRUD(self.janela, self.app, resultado)
            else:
                messagebox.showerror("ERROR", "CPF ou senha incorretos!")
        except sqlite3.Error as e:
            messagebox.showerror("ERROR", f"Erro ao verificar login: {e}")

class TelaCRUD:
    def __init__(self, janela_principal, app, usuario_info):
        self.janela = janela_principal
        self.app = app
        self.usuario_info = usuario_info  # Dados do usuário logado (nome, setor, função)
        
        self.criar_widgets()
        self.carregar_funcionarios()
    
    def criar_widgets(self):
        # Limpar a janela
        for widget in self.janela.winfo_children():
            widget.destroy()
        
        # Frame principal
        self.frame = tk.Frame(self.janela, bg="#fff", bd=2, relief="groove")
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Barra superior com informações do usuário
        self.barra_superior = tk.Frame(self.frame, bg="#f0f0f0", height=50)
        self.barra_superior.pack(fill="x", pady=(0, 20))
        
        tk.Label(self.barra_superior, text=f"Usuário: {self.usuario_info[0]} | Setor: {self.usuario_info[1]} | Função: {self.usuario_info[2]}", 
                bg="#f0f0f0", font=("Arial", 10)).pack(side="left", padx=10)
        
        tk.Button(self.barra_superior, text="Sair", font=("Arial", 10), 
                 command=self.app.criar_tela_inicial).pack(side="right", padx=10)
        
        # Frame para os controles CRUD
        self.controles_frame = tk.Frame(self.frame, bg="#fff")
        self.controles_frame.pack(fill="x", pady=(0, 10))
        
        # Botões CRUD
        tk.Button(self.controles_frame, text="Adicionar Funcionário", command=self.mostrar_formulario_adicionar,
                 bg="#4CAF50", fg="white").pack(side="left", padx=5)
        tk.Button(self.controles_frame, text="Editar", command=self.editar_funcionario,
                 bg="#2196F3", fg="white").pack(side="left", padx=5)
        tk.Button(self.controles_frame, text="Excluir", command=self.excluir_funcionario,
                 bg="#f44336", fg="white").pack(side="left", padx=5)
        tk.Button(self.controles_frame, text="Atualizar Lista", command=self.carregar_funcionarios,
                 bg="#607D8B", fg="white").pack(side="right", padx=5)
        
        # Treeview para exibir os funcionários
        self.tree_frame = tk.Frame(self.frame)
        self.tree_frame.pack(fill="both", expand=True)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=("CPF", "Nome", "Email", "Setor"), show="headings")
        
        # Configurar colunas
        self.tree.heading("CPF", text="CPF")
        self.tree.heading("Nome", text="Nome")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Setor", text="Setor")
        
        self.tree.column("CPF", width=120)
        self.tree.column("Nome", width=150)
        self.tree.column("Email", width=180)
        self.tree.column("Setor", width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(fill="both", expand=True)
    
    def carregar_funcionarios(self):
        # Limpar a treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            self.app.cursor.execute("SELECT CPF, Nome, Email, Nome_Setor FROM Funcionarios")
            funcionarios = self.app.cursor.fetchall()
            
            for func in funcionarios:
                cpf_str = str(func[0]).zfill(11)
                cpf_formatado = f"{cpf_str[:3]}.{cpf_str[3:6]}.{cpf_str[6:9]}-{cpf_str[9:]}"
                self.tree.insert("", "end", values=(cpf_formatado, func[1], func[2], func[3]))

        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao carregar funcionários: {e}")
    
    def mostrar_formulario_adicionar(self):
        # Janela de formulário para adicionar novo funcionário
        self.formulario = tk.Toplevel(self.janela)
        self.formulario.title("Adicionar Funcionário")
        self.formulario.geometry("400x500")
        self.formulario.resizable(False, False)
        
        # CPF
        tk.Label(self.formulario, text="CPF:").pack(pady=(10, 0))
        self.cpf_entry = tk.Entry(self.formulario)
        self.cpf_entry.pack(pady=5)
        self.cpf_entry.bind("<KeyRelease>", self.formatar_cpf_formulario)
        
        # Nome
        tk.Label(self.formulario, text="Nome:").pack(pady=(10, 0))
        self.nome_entry = tk.Entry(self.formulario)
        self.nome_entry.pack(pady=5)
        
        # Email
        tk.Label(self.formulario, text="Email:").pack(pady=(10, 0))
        self.email_entry = tk.Entry(self.formulario)
        self.email_entry.pack(pady=5)
        
        # Senha
        tk.Label(self.formulario, text="Senha:").pack(pady=(10, 0))
        self.senha_entry = tk.Entry(self.formulario, show="*")
        self.senha_entry.pack(pady=5)
        
        # Setor
        tk.Label(self.formulario, text="Setor:").pack(pady=(10, 0))
        
        # Obter setores disponíveis
        try:
            self.app.cursor.execute("SELECT Nome_Setor FROM Setor")
            setores = [row[0] for row in self.app.cursor.fetchall()]
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao carregar setores: {e}")
            setores = []
        
        self.setor_var = tk.StringVar(self.formulario)
        self.setor_var.set(setores[0] if setores else "")
        self.setor_menu = tk.OptionMenu(self.formulario, self.setor_var, *setores)
        self.setor_menu.pack(pady=5)
        
        # Botões
        botoes_frame = tk.Frame(self.formulario)
        botoes_frame.pack(pady=20)
        
        tk.Button(botoes_frame, text="Salvar", command=self.salvar_funcionario, 
                 bg="#4CAF50", fg="white").pack(side="left", padx=10)
        tk.Button(botoes_frame, text="Cancelar", command=self.formulario.destroy,
                 bg="#f44336", fg="white").pack(side="right", padx=10)
    
    def formatar_cpf_formulario(self, event):
        cpf = self.cpf_entry.get()
        cpf = re.sub(r'[^0-9]', '', cpf)
        
        if len(cpf) > 11:
            cpf = cpf[:11]

        cpf_formatado = ""
        for i in range(len(cpf)):
            if i in [3, 6]:
                cpf_formatado += "."
            elif i == 9:
                cpf_formatado += "-"
            cpf_formatado += cpf[i]
        
        self.cpf_entry.delete(0, tk.END)
        self.cpf_entry.insert(0, cpf_formatado)
    
    def salvar_funcionario(self):
        # Validar campos
        cpf = re.sub(r'[^0-9]', '', self.cpf_entry.get())
        nome = self.nome_entry.get()
        email = self.email_entry.get()
        senha = self.senha_entry.get()
        setor = self.setor_var.get()
        
        if not all([cpf, nome, email, senha, setor]):
            messagebox.showerror("Erro", "Todos os campos são obrigatórios!")
            return
        
        if len(cpf) != 11:
            messagebox.showerror("Erro", "CPF inválido!")
            return
        
        if not self.validar_email(email):
            messagebox.showerror("Erro", "Email inválido!")
            return
        
        try:
            # Verificar se CPF já existe
            self.app.cursor.execute("SELECT 1 FROM Funcionarios WHERE CPF = ?", (cpf,))
            if self.app.cursor.fetchone():
                messagebox.showerror("Erro", "CPF já cadastrado!")
                return
            
            # Verificar se email já existe
            self.app.cursor.execute("SELECT 1 FROM Funcionarios WHERE Email = ?", (email,))
            if self.app.cursor.fetchone():
                messagebox.showerror("Erro", "Email já cadastrado!")
                return
            
            # Inserir novo funcionário
            self.app.cursor.execute(
                "INSERT INTO Funcionarios (CPF, Nome, Email, Senha, Nome_Setor) VALUES (?, ?, ?, ?, ?)",
                (cpf, nome, email, senha, setor)
            )
            self.app.conn.commit()
            
            messagebox.showinfo("Sucesso", "Funcionário adicionado com sucesso!")
            self.formulario.destroy()
            self.carregar_funcionarios()
            
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao salvar funcionário: {e}")
    
    def validar_email(self, email):
        padrao = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(padrao, email) is not None
    
    def editar_funcionario(self):
        # Obter item selecionado
        selecionado = self.tree.selection()
        if not selecionado:
            messagebox.showwarning("Aviso", "Selecione um funcionário para editar!")
            return
        
        item = self.tree.item(selecionado[0])
        cpf_formatado = item['values'][0]
        cpf = re.sub(r'[^0-9]', '', cpf_formatado)
        
        try:
            # Obter dados do funcionário
            self.app.cursor.execute("SELECT Nome, Email, Nome_Setor FROM Funcionarios WHERE CPF = ?", (cpf,))
            funcionario = self.app.cursor.fetchone()
            
            if not funcionario:
                messagebox.showerror("Erro", "Funcionário não encontrado!")
                return
            
            # Janela de edição
            self.formulario_edicao = tk.Toplevel(self.janela)
            self.formulario_edicao.title("Editar Funcionário")
            self.formulario_edicao.geometry("400x450")
            self.formulario_edicao.resizable(False, False)
            
            # CPF (não editável)
            tk.Label(self.formulario_edicao, text="CPF:").pack(pady=(10, 0))
            cpf_entry = tk.Entry(self.formulario_edicao, state="readonly")
            cpf_entry.pack(pady=5)
            cpf_entry.insert(0, cpf_formatado)
            
            # Nome
            tk.Label(self.formulario_edicao, text="Nome:").pack(pady=(10, 0))
            self.nome_edit_entry = tk.Entry(self.formulario_edicao)
            self.nome_edit_entry.pack(pady=5)
            self.nome_edit_entry.insert(0, funcionario[0])
            
            # Email
            tk.Label(self.formulario_edicao, text="Email:").pack(pady=(10, 0))
            self.email_edit_entry = tk.Entry(self.formulario_edicao)
            self.email_edit_entry.pack(pady=5)
            self.email_edit_entry.insert(0, funcionario[1])
            
            # Senha (opcional)
            tk.Label(self.formulario_edicao, text="Nova Senha (deixe em branco para manter a atual):").pack(pady=(10, 0))
            self.senha_edit_entry = tk.Entry(self.formulario_edicao, show="*")
            self.senha_edit_entry.pack(pady=5)
            
            # Setor
            tk.Label(self.formulario_edicao, text="Setor:").pack(pady=(10, 0))
            
            # Obter setores disponíveis
            try:
                self.app.cursor.execute("SELECT Nome_Setor FROM Setor")
                setores = [row[0] for row in self.app.cursor.fetchall()]
            except sqlite3.Error as e:
                messagebox.showerror("Erro", f"Erro ao carregar setores: {e}")
                setores = []
            
            self.setor_edit_var = tk.StringVar(self.formulario_edicao)
            self.setor_edit_var.set(funcionario[2])  # Setor atual
            self.setor_edit_menu = tk.OptionMenu(self.formulario_edicao, self.setor_edit_var, *setores)
            self.setor_edit_menu.pack(pady=5)
            
            # Botões
            botoes_frame = tk.Frame(self.formulario_edicao)
            botoes_frame.pack(pady=20)
            
            tk.Button(botoes_frame, text="Salvar", command=lambda: self.salvar_edicao(cpf), 
                     bg="#4CAF50", fg="white").pack(side="left", padx=10)
            tk.Button(botoes_frame, text="Cancelar", command=self.formulario_edicao.destroy,
                     bg="#f44336", fg="white").pack(side="right", padx=10)
            
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao carregar dados do funcionário: {e}")
    
    def salvar_edicao(self, cpf):
        # Obter dados do formulário
        nome = self.nome_edit_entry.get()
        email = self.email_edit_entry.get()
        senha = self.senha_edit_entry.get()
        setor = self.setor_edit_var.get()
        
        if not all([nome, email, setor]):
            messagebox.showerror("Erro", "Nome, Email e Setor são obrigatórios!")
            return
        
        if not self.validar_email(email):
            messagebox.showerror("Erro", "Email inválido!")
            return
        
        try:
            # Verificar se o novo email já pertence a outro funcionário
            self.app.cursor.execute("SELECT CPF FROM Funcionarios WHERE Email = ? AND CPF != ?", (email, cpf))
            if self.app.cursor.fetchone():
                messagebox.showerror("Erro", "Email já está em uso por outro funcionário!")
                return
            
            # Atualizar dados
            if senha:  # Se foi fornecida uma nova senha
                self.app.cursor.execute(
                    "UPDATE Funcionarios SET Nome = ?, Email = ?, Senha = ?, Nome_Setor = ? WHERE CPF = ?",
                    (nome, email, senha, setor, cpf)
                )
            else:  # Manter a senha atual
                self.app.cursor.execute(
                    "UPDATE Funcionarios SET Nome = ?, Email = ?, Nome_Setor = ? WHERE CPF = ?",
                    (nome, email, setor, cpf)
                )
            
            self.app.conn.commit()
            messagebox.showinfo("Sucesso", "Dados do funcionário atualizados com sucesso!")
            self.formulario_edicao.destroy()
            self.carregar_funcionarios()
            
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao atualizar funcionário: {e}")
    
    def excluir_funcionario(self):
        # Obter item selecionado
        selecionado = self.tree.selection()
        if not selecionado:
            messagebox.showwarning("Aviso", "Selecione um funcionário para excluir!")
            return
        
        item = self.tree.item(selecionado[0])
        cpf_formatado = item['values'][0]
        nome = item['values'][1]
        
        # Confirmar exclusão
        resposta = messagebox.askyesno(
            "Confirmar Exclusão",
            f"Tem certeza que deseja excluir o funcionário {nome} (CPF: {cpf_formatado})?"
        )
        
        if not resposta:
            return
        
        cpf = re.sub(r'[^0-9]', '', cpf_formatado)
        
        try:
            self.app.cursor.execute("DELETE FROM Funcionarios WHERE CPF = ?", (cpf,))
            self.app.conn.commit()
            
            messagebox.showinfo("Sucesso", "Funcionário excluído com sucesso!")
            self.carregar_funcionarios()
            
        except sqlite3.Error as e:
            messagebox.showerror("Erro", f"Erro ao excluir funcionário: {e}")

if __name__ == "__main__":
    app = Aplicacao() 
