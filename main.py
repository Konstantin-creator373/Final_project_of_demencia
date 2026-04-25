from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import secrets
from contextlib import contextmanager
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'super_shmooper_secret_key'

DATABASE = 'survey.db'

key_to_VIP = "http://127.0.0.1:5000/admin/stats?key=secret_key_to_VIP"

DEMENTIA_THRESHOLDS = {
    'yes_threshold': 2,
    'sometimes_threshold': 3,
    'critical_questions': [2, 3, 4, 5, 6]
}


def analyze_dementia_risk(answers):
    risk_score = 0
    yes_count = 0
    sometimes_count = 0
    no_count = 0

    for i, answer_dict in enumerate(answers):
        if i == 0:
            continue

        answer = answer_dict['answer']
        if answer == 'Да':
            yes_count += 1
            risk_score += 3
        elif answer == 'Иногда':
            sometimes_count += 1
            risk_score += 1
        elif answer == 'Нет':
            no_count += 1

    total_considered = yes_count + sometimes_count + no_count

    if yes_count >= DEMENTIA_THRESHOLDS['yes_threshold'] or sometimes_count >= DEMENTIA_THRESHOLDS[
        'sometimes_threshold']:
        risk_level = 'high'
        message = 'ВНИМАНИЕ: Ваши ответы указывают на возможные признаки ранней деменции!'
        recommendation = 'Настоятельно рекомендуем обратиться к неврологу для профессиональной консультации и диагностики.'
        icon = '⚠️'
        color = '#e74c3c'
        bg_color = '#ffe0e0'
    elif yes_count >= 1 or sometimes_count >= 2:
        risk_level = 'medium'
        message = '🔍 ОБРАТИТЕ ВНИМАНИЕ: У вас есть некоторые факторы риска'
        recommendation = 'Рекомендуем проконсультироваться с врачом и следить за своим состоянием.'
        icon = '🔍'
        color = '#f39c12'
        bg_color = '#fff3e0'
    else:
        risk_level = 'low'
        message = '✅ Хорошие новости: значительных признаков деменции не обнаружено'
        recommendation = 'Продолжайте вести здоровый образ жизни и регулярно проходите профилактические осмотры.'
        icon = '✅'
        color = '#27ae60'
        bg_color = '#e0f5e8'

    details = {
        'yes_count': yes_count,
        'sometimes_count': sometimes_count,
        'no_count': no_count,
        'risk_score': risk_score
    }

    return risk_level, message, recommendation, icon, color, bg_color, details


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
            max-width: 700px;
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
        .warning-box {
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            border-left: 5px solid;
            animation: slideIn 0.5s ease-out;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .warning-icon {
            font-size: 48px;
            text-align: center;
            margin-bottom: 15px;
        }
        .warning-message {
            font-size: 20px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 15px;
        }
        .warning-recommendation {
            font-size: 16px;
            text-align: center;
            margin-bottom: 20px;
        }
        .risk-details {
            background: rgba(0,0,0,0.05);
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
            font-size: 14px;
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
            font-weight: 600;
            text-align: right;
            flex: 1;
        }
        .answer-high-risk {
            color: #e74c3c;
        }
        .answer-medium-risk {
            color: #f39c12;
        }
        .answer-low-risk {
            color: #27ae60;
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
        .stats {
            display: flex;
            justify-content: space-around;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .stat-item {
            text-align: center;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .disclaimer {
            font-size: 12px;
            color: #999;
            text-align: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">{{ icon }}</div>
        <h1>Спасибо за ваши ответы!</h1>

        <div class="warning-box" style="background: {{ bg_color }}; border-left-color: {{ color }};">
            <div class="warning-icon">{{ icon }}</div>
            <div class="warning-message" style="color: {{ color }};">{{ warning_message }}</div>
            <div class="warning-recommendation">{{ recommendation }}</div>
            <div class="risk-details">
                <strong>Детальный анализ:</strong><br>
                • Ответов "Да": {{ details.yes_count }}<br>
                • Ответов "Иногда": {{ details.sometimes_count }}<br>
                • Ответов "Нет": {{ details.no_count }}<br>
                • Общий балл риска: {{ details.risk_score }}/15
            </div>
        </div>

        <h2>Ваши ответы:</h2>
        <ul class="answers-list">
            {% for item in answers %}
            <li class="answer-item">
                <span class="answer-question">{{ item.question }}</span>
                <span class="answer-value 
                    {% if loop.index0 > 0 %}
                        {% if item.answer == 'Да' %}answer-high-risk
                        {% elif item.answer == 'Иногда' %}answer-medium-risk
                        {% else %}answer-low-risk
                        {% endif %}
                    {% endif %}">
                    {{ item.answer }}
                </span>
            </li>
            {% endfor %}
        </ul>

        <div class="stats">
            <div class="stat-item">
                <div class="stat-number" style="color: #e74c3c;">{{ details.yes_count }}</div>
                <div class="stat-label">Ответов "Да"</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" style="color: #f39c12;">{{ details.sometimes_count }}</div>
                <div class="stat-label">Ответов "Иногда"</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" style="color: #27ae60;">{{ details.no_count }}</div>
                <div class="stat-label">Ответов "Нет"</div>
            </div>
        </div>

        <a href="/restart" class="btn">Пройти заново ↻</a>

        <div class="disclaimer">
            ⚕️ Данный опрос носит информационный характер и не заменяет профессиональную медицинскую диагностику. 
            При наличии симптомов обязательно обратитесь к врачу.
        </div>
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

    risk_level, warning_message, recommendation, icon, color, bg_color, details = analyze_dementia_risk(
        session['answers'])

    return render_template_string(
        RESULT_TEMPLATE,
        answers=session['answers'],
        warning_message=warning_message,
        recommendation=recommendation,
        icon=icon,
        color=color,
        bg_color=bg_color,
        details=details,
        risk_level=risk_level
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
