from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import secrets
from contextlib import contextmanager
import hashlib

app = Flask(__name__)
app.secret_key = 'super_shmooper_secret_key'

DATABASE = 'survey.db'


def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                question_id INTEGER,
                question_text TEXT,
                answer TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        conn.execute('CREATE INDEX IF NOT EXISTS idx_answers_user_id ON answers(user_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_answers_submitted_at ON answers(submitted_at)')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                action TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def sanitize_input(input_string):
    if not input_string:
        return ""
    import re
    clean = re.sub(r'[<>{}]', '', str(input_string))
    return clean[:500]


def get_user_id(session_id):
    with get_db() as conn:
        user = conn.execute(
            'SELECT id FROM users WHERE session_id = ?',
            (session_id,)
        ).fetchone()

        if user:
            return user['id']

        cursor = conn.execute(
            'INSERT INTO users (session_id) VALUES (?)',
            (session_id,)
        )
        return cursor.lastrowid


def log_security_event(session_id, action, ip_address, user_agent):
    with get_db() as conn:
        conn.execute(
            'INSERT INTO security_log (session_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)',
            (session_id, action, ip_address, user_agent)
        )
        conn.commit()


QUESTIONS = [
    {
        'id': 1,
        'question': 'Сколько вам лет?',
        'type': 'text',
        'placeholder': 'Введите возраст'
    },
    {
        'id': 2,
        'question': 'Есть ли у вас родственники с деменцией?',
        'type': 'choice',
        'options': ['Да', 'Нет']
    },
    {
        'id': 3,
        'question': 'Замечали ли вы у себя ухудшение краткосрочной памяти?',
        'type': 'choice',
        'options': ['Да', 'Иногда', 'Нет']
    },
    {
        'id': 4,
        'question': 'Бывает ли вам трудно выполнить повседневные дела которые вы выполняли много раз?',
        'type': 'choice',
        'options': ['Да', 'Иногда', 'Нет']
    },
    {
        'id': 5,
        'question': 'Замечали ли вы у себя беспричинную агрессию?',
        'type': 'choice',
        'options': ['Да', 'Иногда', 'Нет']
    },
    {
        'id': 6,
        'question': 'Замечали ли вы у себя проблемы с речью и мышлением?',
        'type': 'choice',
        'options': ['Да', 'Иногда', 'Нет']
    }
]

QUESTION_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Опрос | Вопрос {{ current_question + 1 }} из {{ total_questions }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            margin-bottom: 30px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .question-number {
            color: #667eea;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .question-text {
            font-size: 24px;
            color: #333;
            margin-bottom: 30px;
            line-height: 1.4;
        }
        .form-group {
            margin-bottom: 25px;
        }
        .form-control {
            width: 100%;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-control:focus {
            outline: none;
            border-color: #667eea;
        }
        .choice-group {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .choice-option {
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
        }
        .choice-option:hover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .choice-option input {
            margin-right: 15px;
            width: 20px;
            height: 20px;
        }
        .choice-option.selected {
            border-color: #667eea;
            background: #f0f3ff;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .error {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 10px;
            display: none;
        }
        .error.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="progress-bar">
            <div class="progress-fill" style="width: {{ ((current_question + 1) / total_questions) * 100 }}%"></div>
        </div>

        <div class="question-number">Вопрос {{ current_question + 1 }} из {{ total_questions }}</div>
        <h1 class="question-text">{{ question.question }}</h1>

        <form id="questionForm" method="POST" action="/submit_answer">
            {% if question.type == 'text' or question.type == 'number' %}
                <div class="form-group">
                    <input 
                        type="{{ question.type }}" 
                        name="answer" 
                        class="form-control" 
                        placeholder="{{ question.placeholder }}"
                        {% if question.get('required', True) %}required{% endif %}
                    >
                </div>
            {% elif question.type == 'choice' %}
                <div class="form-group choice-group">
                    {% for option in question.options %}
                        <label class="choice-option">
                            <input type="radio" name="answer" value="{{ option }}" required>
                            {{ option }}
                        </label>
                    {% endfor %}
                </div>
            {% endif %}

            <div class="error" id="errorMsg">Пожалуйста, ответьте на вопрос</div>
            <button type="submit" class="btn">
                {% if current_question + 1 < total_questions %}
                    Далее →
                {% else %}
                    Завершить ✓
                {% endif %}
            </button>
        </form>
    </div>

    <script>
        document.querySelectorAll('.choice-option').forEach(option => {
            option.addEventListener('click', function() {
                document.querySelectorAll('.choice-option').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
            });
        });

        document.getElementById('questionForm').addEventListener('submit', function(e) {
            const answer = document.querySelector('[name="answer"]:checked') || 
                          document.querySelector('[name="answer"]');
            if (!answer || (answer.type !== 'radio' && !answer.value)) {
                e.preventDefault();
                document.getElementById('errorMsg').classList.add('show');
            }
        });
    </script>
</body>
</html>
"""

RESULT_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Результаты опроса</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            width: 100%;
        }
        .success-icon {
            font-size: 60px;
            text-align: center;
            margin-bottom: 20px;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .answers-list {
            list-style: none;
            margin-bottom: 30px;
        }
        .answer-item {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
        }
        .answer-item:last-child {
            border-bottom: none;
        }
        .answer-question {
            color: #666;
            font-size: 14px;
            flex: 1;
        }
        .answer-value {
            color: #667eea;
            font-weight: 600;
            text-align: right;
            flex: 1;
        }
        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            text-decoration: none;
            display: block;
            text-align: center;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">🎉</div>
        <h1>Спасибо за ответы! Они помогут исследовательским центрам
        и институтам</h1>

        <ul class="answers-list">
            {% for item in answers %}
            <li class="answer-item">
                <span class="answer-question">{{ item.question }}</span>
                <span class="answer-value">{{ item.answer }}</span>
            </li>
            {% endfor %}
        </ul>

        <a href="/restart" class="btn">Пройти заново ↻</a>
    </div>
</body>
</html>
"""


@app.route('/')
def index():
    if 'session_uuid' not in session:
        session['session_uuid'] = secrets.token_hex(32)

    if 'current_question' not in session:
        session['current_question'] = 0
        session['answers'] = []

        log_security_event(
            session['session_uuid'],
            'survey_started',
            request.remote_addr,
            request.user_agent.string
        )

    current_q = session['current_question']

    if current_q >= len(QUESTIONS):
        return redirect(url_for('results'))

    return render_template_string(
        QUESTION_TEMPLATE,
        question=QUESTIONS[current_q],
        current_question=current_q,
        total_questions=len(QUESTIONS)
    )


@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    if 'session_uuid' not in session or 'current_question' not in session:
        return redirect(url_for('index'))

    answer = request.form.get('answer', '').strip()

    if not answer:
        log_security_event(
            session.get('session_uuid', 'unknown'),
            'empty_answer_attempt',
            request.remote_addr,
            request.user_agent.string
        )
        return redirect(url_for('index'))

    clean_answer = sanitize_input(answer)

    current_q = session['current_question']

    if current_q >= len(QUESTIONS):
        return redirect(url_for('results'))

    question = QUESTIONS[current_q]

    try:
        user_id = get_user_id(session['session_uuid'])

        with get_db() as conn:
            conn.execute('''
                INSERT INTO answers (user_id, question_id, question_text, answer)
                VALUES (?, ?, ?, ?)
            ''', (user_id, question['id'], question['question'], clean_answer))
            conn.commit()

        log_security_event(
            session['session_uuid'],
            f'answered_q{question["id"]}',
            request.remote_addr,
            request.user_agent.string
        )

    except Exception as e:
        log_security_event(
            session.get('session_uuid', 'unknown'),
            f'db_error: {str(e)[:100]}',
            request.remote_addr,
            request.user_agent.string
        )

        if 'answers' not in session:
            session['answers'] = []
        session['answers'].append({
            'question': question['question'],
            'answer': clean_answer
        })

    if 'answers' not in session:
        session['answers'] = []

    session['answers'].append({
        'question': question['question'],
        'answer': clean_answer
    })

    session['current_question'] += 1
    session.modified = True

    return redirect(url_for('index'))


@app.route('/results')
def results():
    if 'answers' not in session or not session['answers']:
        return redirect(url_for('index'))

    if 'session_uuid' in session:
        log_security_event(
            session['session_uuid'],
            'survey_completed',
            request.remote_addr,
            request.user_agent.string
        )

    return render_template_string(
        RESULT_TEMPLATE,
        answers=session['answers']
    )


@app.route('/restart')
def restart():
    if 'session_uuid' in session:
        log_security_event(
            session['session_uuid'],
            'survey_restarted',
            request.remote_addr,
            request.user_agent.string
        )

    session.clear()

    session['session_uuid'] = secrets.token_hex(32)
    session['current_question'] = 0
    session['answers'] = []

    log_security_event(
        session['session_uuid'],
        'survey_restarted_new',
        request.remote_addr,
        request.user_agent.string
    )

    return redirect(url_for('index'))


@app.route('/admin/stats')
def admin_stats():
    auth_key = request.args.get('key', '')
    if auth_key != 'secret_key_to_VIP':
        return "Доступ запрещен", 403

    with get_db() as conn:
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_answers = conn.execute('SELECT COUNT(*) as count FROM answers').fetchone()['count']

        answers_stats = []
        for q in QUESTIONS:
            stats = conn.execute('''
                SELECT answer, COUNT(*) as count 
                FROM answers 
                WHERE question_id = ? 
                GROUP BY answer
            ''', (q['id'],)).fetchall()

            answers_stats.append({
                'question': q['question'],
                'stats': [dict(stat) for stat in stats]
            })

        suspicious_activity = conn.execute('''
            SELECT * FROM security_log 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''').fetchall()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Статистика опроса</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            h1 { color: #667eea; }
            .stat-card { background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 10px; }
            .suspicious { background: #ffe0e0; padding: 10px; margin: 5px 0; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Статистика опроса</h1>
        <div class="stat-card">
            <strong>Всего пользователей:</strong> {{ total_users }}<br>
            <strong>Всего ответов:</strong> {{ total_answers }}
        </div>

        <h2>Статистика по вопросам</h2>
        {% for q in answers_stats %}
        <div class="stat-card">
            <strong>{{ q.question }}</strong><br>
            {% for stat in q.stats %}
                {{ stat.answer }}: {{ stat.count }}<br>
            {% endfor %}
        </div>
        {% endfor %}

    </body>
    </html>
    """

    return render_template_string(html,
                                  total_users=total_users,
                                  total_answers=total_answers,
                                  answers_stats=answers_stats,
                                  suspicious_activity=suspicious_activity)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)