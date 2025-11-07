# -*- coding: utf-8 -*-
import sys
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, send_from_directory
from datetime import datetime, timezone
from functools import wraps 
# 비밀번호 해시를 위한 라이브러리
from werkzeug.security import generate_password_hash, check_password_hash 
# 파일 업로드 관련 라이브러리
from werkzeug.utils import secure_filename
from pathlib import Path 

# =================================================================
# [필수 수정: UnicodeEncodeError 방지]
# 파이썬의 표준 입출력 스트림이 UTF-8 인코딩을 사용하도록 강제합니다.
try:
    if sys.stdout.encoding != 'utf-8':
        # stdout을 UTF-8 인코딩으로 다시 열어 설정 (버퍼링=1로 라인 버퍼링 설정)
        sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
    if sys.stderr.encoding != 'utf-8':
        sys.stderr = open(sys.stderr.fileno(), mode='w', encoding='utf-8', buffering=1)
except Exception as e:
    # 환경에 따라 이 작업이 실패할 수 있으므로, 에러를 무시하고 진행
    pass
# =================================================================

# Flask 앱 설정
app = Flask(__name__, instance_relative_config=True)
app.secret_key = '전주공고_메이커스페이스_임시_시크릿키_2025'

# 파일 업로드 설정
UPLOAD_FOLDER_NAME = 'uploads'
# app.instance_path 내부에 'uploads' 폴더 생성
app.config['UPLOAD_FOLDER'] = Path(app.instance_path) / UPLOAD_FOLDER_NAME
# 16MB 제한 설정 (필요에 따라 변경)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 허용되는 확장자 (이미지 및 동영상)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}

# 폴더가 없으면 생성
if not app.config['UPLOAD_FOLDER'].exists():
    app.config['UPLOAD_FOLDER'].mkdir(parents=True, exist_ok=True)

def allowed_file(filename):
    """허용된 확장자인지 확인합니다."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# =================================================================
# Jinja 필터 추가: 한글 날짜 포맷팅 오류 해결
# =================================================================
def korean_date_format(value):
    """datetime 객체를 받아 'YYYY년 MM월 DD일 HH:MM' 형식의 한글 문자열로 변환하는 Jinja 필터입니다."""
    if not isinstance(value, datetime):
        # 문자열을 datetime 객체로 변환 시도
        try:
            # ISO 8601 형식 문자열에서 'Z'를 +00:00으로 대체하여 datetime 객체로 변환
            value = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        except ValueError:
            return str(value)

    # 타임존 정보 제거 후 한국 시간대(KST)로 간주하고 출력 (실제 운영 시에는 timezone 설정 권장)
    value = value.replace(tzinfo=None)
    
    return value.strftime('%Y') + '년 ' + \
           value.strftime('%m') + '월 ' + \
           value.strftime('%d') + '일 ' + \
           value.strftime('%H') + ':' + \
           value.strftime('%M')

app.jinja_env.filters['korean_date_format'] = korean_date_format

# =================================================================
# IP 주소 및 Audit Log 관련 함수 (보안 로깅)
# =================================================================

def get_remote_addr():
    """요청자의 IP 주소를 가져옵니다. 프록시 환경(예: Heroku)을 고려합니다."""
    # X-Forwarded-For 헤더는 프록시를 통과할 때 원본 IP를 저장합니다.
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def log_action(action, user_id, post_id=None, details=None):
    """
    활동 로그를 audit_logs 테이블에 기록합니다. (보안 목적)
    action: 'POST_CREATED', 'LOGIN_SUCCESS', 'MEMBER_ACCEPT', 'USER_BANNED' 등
    """
    db = get_db()
    ip_address = get_remote_addr()
    
    # [보안 기록] audit_logs 테이블에 기록
    db.execute("""
        INSERT INTO audit_logs (timestamp, user_id, action, post_id, ip_address, details) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now(timezone.utc).isoformat(), user_id, action, post_id, ip_address, details))
    db.commit()


# =================================================================
# SQLite 데이터베이스 설정 및 초기화
# =================================================================

def get_db():
    """데이터베이스 연결을 가져오거나 새로 생성합니다."""
    db = getattr(g, '_database', None)
    if db is None:
        db_path = os.path.join(app.instance_path, 'makerspace.db')
        
        if not os.path.exists(app.instance_path):
            os.makedirs(app.instance_path)

        db = g._database = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """요청이 끝날 때 데이터베이스 연결을 닫습니다."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """데이터베이스 테이블을 초기화하고 초기 데이터를 삽입합니다."""
    db = get_db()
    
    # 1. users 테이블: 동아리 멤버 정보를 저장
    db.execute("""
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL, 
            is_member INTEGER NOT NULL,
            is_banned INTEGER NOT NULL DEFAULT 0
        );
    """)
    
    # 2. posts 테이블: 활동 기록을 저장
    db.execute("""
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            file_path TEXT -- 파일 경로 저장 컬럼
        );
    """)
    
    # 3. audit_logs 테이블: 보안 및 활동 감사를 위한 로그 기록
    db.execute("""
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL, 
            action TEXT NOT NULL, 
            post_id INTEGER, 
            ip_address TEXT,
            details TEXT
        );
    """)

    # 4. member_applications 테이블: 멤버 가입 신청 대기 목록
    db.execute("""
        CREATE TABLE member_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)
    
    # 5. report_logs 테이블: 신고 기록
    db.execute("""
        CREATE TABLE report_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id TEXT NOT NULL,
            reported_type TEXT NOT NULL, -- 'POST' or 'COMMENT(Post ID)'
            reported_id INTEGER NOT NULL,
            reported_content TEXT,
            reason TEXT,
            processed INTEGER NOT NULL DEFAULT 0, -- 0: 미처리, 1: 처리됨
            reported_at TEXT NOT NULL
        );
    """)

    # 초기 동아리 멤버 및 활동 기록 삽입
    initial_hashed_pw = generate_password_hash("1234")
    # 최상위 관리자 계정은 is_admin 플래그를 통해 확인되지만, 일반 멤버와 동일하게 is_member=1로 설정
    db.execute("INSERT INTO users (id, password, is_member) VALUES (?, ?, ?)", 
               ("makerspace_jj", initial_hashed_pw, 1)) 
    
    db.execute("INSERT INTO posts (title, content, author, created_at) VALUES (?, ?, ?, ?)",
               ('첫 번째 활동 기록: 3D 프린팅', '메이커 스페이스 첫 프로젝트를 시작했습니다. 3D 프린팅 연습 중입니다.', '김메이커', datetime(2025, 10, 20, 14, 30, tzinfo=timezone.utc).isoformat()))
    db.execute("INSERT INTO posts (title, content, author, created_at) VALUES (?, ?, ?, ?)",
               ('회로 설계 및 테스트 완료', '아두이노를 이용한 센서 회로를 설계하고 작동 테스트를 완료했습니다.', '박스페이스', datetime(2025, 10, 25, 9, 0, tzinfo=timezone.utc).isoformat()))
    
    db.commit()

# 앱 시작 시 DB 초기화 확인 및 실행 (테이블 마이그레이션 포함)
with app.app_context():
    db = get_db()
    cursor = db.cursor()
    
    # ⭐ [수정] 1. report_logs 테이블 존재 확인 로직을 최상단으로 이동하여 
    #            테이블이 없으면 먼저 init_db()를 호출하여 테이블을 모두 생성하도록 함.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='report_logs';")
    if cursor.fetchone() is None:
        # report_logs 테이블이 없으면 전체 초기화 (개발 환경에서만 안전)
        print("데이터베이스 초기 테이블이 감지되지 않았습니다. 전체 DB를 초기화합니다.")
        try:
            db.execute("DROP TABLE IF EXISTS users;")
            db.execute("DROP TABLE IF EXISTS posts;")
            db.execute("DROP TABLE IF EXISTS audit_logs;")
            db.execute("DROP TABLE IF EXISTS member_applications;")
            db.execute("DROP TABLE IF EXISTS report_logs;")
        except sqlite3.OperationalError:
            pass # 테이블이 없으면 무시
        init_db() # 이 시점에서 모든 테이블(posts 포함)이 생성됨
    
    # ⭐ [수정] 2. init_db() 호출 후, 테이블이 확실히 존재할 때 컬럼 마이그레이션을 시도합니다.

    # posts 테이블에 file_path 컬럼이 없는 경우 추가 (기존 DB 사용 시)
    try:
        db.execute("SELECT file_path FROM posts LIMIT 1")
    except sqlite3.OperationalError:
        # 컬럼 추가
        db.execute("ALTER TABLE posts ADD COLUMN file_path TEXT")
        
    # users 테이블 is_banned 컬럼 확인 로직 유지
    try:
        db.execute("SELECT is_banned FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # 컬럼 추가 및 기본값 설정
        db.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")
        
    db.commit()


# =================================================================
# 유틸리티 함수 및 데코레이터
# =================================================================

def row_to_post(row):
    """SQLite Row 객체를 Jinja 템플릿이 예상하는 딕셔너리 형태로 변환합니다."""
    if not row: return None
    post = dict(row)
    try:
        # ISO 형식 문자열을 datetime 객체로 변환
        post['created_at'] = datetime.fromisoformat(post['created_at'].replace('Z', '+00:00'))
    except ValueError:
        post['created_at'] = datetime.now(timezone.utc)
    return post

# 로그인 상태 확인 및 리다이렉트를 위한 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return decorated_function

# 멤버 권한 확인 및 리다이렉트를 위한 데코레이터
def member_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (g.user and g.user.get('is_member')):
            flash('동아리 멤버만 접근할 수 있습니다.', 'warning')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 확인 및 리다이렉트를 위한 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (g.user and g.user.get('is_admin')):
            flash('관리자만 접근할 수 있습니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 밴 계정 확인 데코레이터
def check_banned(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user and g.user.get('is_banned'):
            flash('정지된 계정은 이 작업을 수행할 수 없습니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# =================================================================
# @app.before_request (로그인 상태 확인 로직)
# =================================================================

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None

    if user_id:
        db = get_db()
        user = db.execute(
            "SELECT id, password, is_member, is_banned FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if user:
            # 관리자 계정 ID는 'makerspace_jj'로 고정
            is_admin_flag = True if user['id'] == 'makerspace_jj' else False
            
            g.user = {
                'id': user['id'], 
                'is_member': bool(user['is_member']), 
                'hashed_pw': user['password'],
                'is_admin': is_admin_flag,
                'is_banned': bool(user['is_banned'])
            }
        
# =================================================================
# 라우팅 및 기능 구현
# =================================================================

# 1. 메인 페이지 (index.html)
@app.route('/')
def index():
    db = get_db()
    posts_data = db.execute(
        "SELECT * FROM posts ORDER BY created_at DESC"
    ).fetchall()
    
    sorted_posts = [row_to_post(post) for post in posts_data]
    
    return render_template('index.html', posts=sorted_posts)

# 2. 활동 기록 작성 페이지 (write.html)
@app.route('/write', methods=['GET', 'POST'])
@member_required
@check_banned
def write():
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = g.user.get('id', '익명') 
        file_path = None # 기본값 설정
        
        # 파일 업로드 처리 로직
        if 'file' in request.files:
            file = request.files['file']
            
            # 파일이 비어있지 않고 허용된 확장자인 경우
            if file.filename != '' and allowed_file(file.filename):
                # secure_filename 사용
                filename = secure_filename(file.filename)
                
                # 파일 이름 충돌 방지를 위해 timestamp와 함께 저장
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                # 파일 확장자 안전하게 분리
                name, ext = os.path.splitext(filename)
                
                safe_filename = f"{timestamp}_{name}{ext}"
                file_path_full = app.config['UPLOAD_FOLDER'] / safe_filename
                
                try:
                    file.save(file_path_full)
                    # DB에는 웹에서 접근 가능한 상대 경로 저장 (예: 'uploads/20251107...')
                    file_path = f"{UPLOAD_FOLDER_NAME}/{safe_filename}" 
                    flash('파일이 성공적으로 업로드되었습니다.', 'info')
                except Exception as e:
                    flash(f'파일 저장 중 오류가 발생했습니다: {e}', 'error')
                    # 파일 저장 실패 시 작성 페이지로 복귀
                    return render_template('write.html')
        
        # 제목 및 내용 필수 확인
        if not title or not content:
            flash('제목과 내용을 모두 입력해 주세요.', 'error')
            return render_template('write.html')
            
        db = get_db()
        cursor = db.execute(
            "INSERT INTO posts (title, content, author, created_at, file_path) VALUES (?, ?, ?, ?, ?)",
            (title, content, user_id, datetime.now(timezone.utc).isoformat(), file_path)
        )
        db.commit()
        
        new_id = cursor.lastrowid
        log_action(action='POST_CREATED', user_id=user_id, post_id=new_id)

        flash('새로운 활동 기록이 성공적으로 작성되었습니다.', 'success')
        return redirect(url_for('detail', post_id=new_id))
    
    return render_template('write.html')

# 3. 상세 보기 페이지 (detail.html)
@app.route('/post/<int:post_id>')
def detail(post_id):
    db = get_db()
    post_row = db.execute(
        "SELECT * FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    post = row_to_post(post_row)
    
    if not post:
        flash('요청하신 글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))

    # 임시 댓글 데이터 (DB 미구현)
    comments = [
        {'username': '방문자1', 'content': '좋은 활동이네요!', 'created_at': datetime.now(timezone.utc)},
    ]
        
    return render_template('detail.html', post=post, comments=comments)


# 파일 업로드 경로 라우팅 (업로드된 파일 제공)
@app.route(f'/{UPLOAD_FOLDER_NAME}/<path:filename>')
def uploaded_file(filename):
    """업로드된 파일을 제공하는 라우트. 파일 시스템 경로 노출 방지."""
    # Pathlib의 Path.name을 사용하여 디렉터리 경로를 포함하지 않는 순수 파일명만 사용하도록 강제 (보안 강화)
    safe_filename_check = Path(secure_filename(filename)).name 
    
    if not safe_filename_check:
        # 파일명이 이상하면 404 처리
        return "File Not Found", 404

    # send_from_directory를 사용하여 안전하게 파일을 제공
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename_check)


# 4. 글 수정 페이지 (edit.html)
@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@member_required
@check_banned
def edit(post_id):
    db = get_db()
    post_row = db.execute(
        "SELECT * FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    post = row_to_post(post_row)

    if not post:
        flash('요청하신 글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    # 작성자 본인 확인 로직
    if post.get('author') != g.user.get('id') and not g.user.get('is_admin'):
        flash('작성자 본인 또는 관리자만 수정할 수 있습니다.', 'danger')
        return redirect(url_for('detail', post_id=post_id))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = g.user.get('id', '익명')
        new_file_path = post.get('file_path') # 기존 파일 경로 유지
        
        # 파일 업로드 처리 로직 (새 파일이 업로드되면 기존 파일 교체)
        if 'file' in request.files:
            file = request.files['file']
            
            if file.filename != '' and allowed_file(file.filename):
                
                # 1. 새 파일 저장
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                name, ext = os.path.splitext(filename)
                safe_filename = f"{timestamp}_{name}{ext}"
                file_path_full = app.config['UPLOAD_FOLDER'] / safe_filename
                
                try:
                    file.save(file_path_full)
                    
                    # 2. 기존 파일 삭제 (새 파일로 교체되었으므로)
                    if new_file_path:
                        # 경로 탐색 방지
                        if new_file_path.startswith(f"{UPLOAD_FOLDER_NAME}/"):
                            old_file_full_path = Path(app.instance_path) / new_file_path
                            if old_file_full_path.exists():
                                os.remove(old_file_full_path)
                            
                    new_file_path = f"{UPLOAD_FOLDER_NAME}/{safe_filename}" # DB에 새 경로 저장
                    flash('새 파일이 성공적으로 업로드 및 교체되었습니다.', 'info')
                    
                except Exception as e:
                    flash(f'파일 저장 중 오류가 발생했습니다: {e}', 'error')
                    return render_template('edit.html', post=post)

        # 'delete_file' 체크박스가 체크되어 있고 파일이 기존에 존재하는 경우
        if request.form.get('delete_file') == 'on' and post.get('file_path'):
             # 기존 파일 삭제
            if new_file_path and new_file_path.startswith(f"{UPLOAD_FOLDER_NAME}/"):
                old_file_full_path = Path(app.instance_path) / new_file_path
                if old_file_full_path.exists():
                    try:
                        os.remove(old_file_full_path)
                        new_file_path = None # DB 경로도 NULL로 설정
                        flash('첨부 파일이 삭제되었습니다.', 'info')
                    except Exception as e:
                        flash(f'첨부 파일 삭제 중 오류가 발생했습니다: {e}', 'error')


        if not title or not content:
            flash('제목과 내용을 모두 입력해 주세요.', 'error')
            return render_template('edit.html', post=post)

        db.execute(
            "UPDATE posts SET title = ?, content = ?, file_path = ? WHERE id = ?",
            (title, content, new_file_path, post_id)
        )
        db.commit()

        log_action(action='POST_UPDATED', user_id=user_id, post_id=post_id)
        
        flash('활동 기록이 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('detail', post_id=post_id))
        
    return render_template('edit.html', post=post)

# 5. 글 삭제 로직
@app.route('/post/<int:post_id>/delete', methods=['POST'])
@member_required
@check_banned
def delete_post(post_id):
    db = get_db()
    
    # 파일 경로 및 작성자 확인을 위해 조회
    post_to_delete = db.execute("SELECT author, file_path FROM posts WHERE id = ?", (post_id,)).fetchone()

    if not post_to_delete:
        flash('삭제할 글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    # 작성자 본인 확인 로직
    if post_to_delete['author'] != g.user.get('id') and not g.user.get('is_admin'):
        flash('작성자 본인 또는 관리자만 삭제할 수 있습니다.', 'danger')
        return redirect(url_for('detail', post_id=post_id))
        
    # 파일 경로가 있는 경우 파일 시스템에서 삭제
    if post_to_delete['file_path']:
        file_path_in_db = post_to_delete['file_path']
        # 경로 탐색 방지
        if file_path_in_db.startswith(f"{UPLOAD_FOLDER_NAME}/"):
            file_to_delete_path = Path(app.instance_path) / file_path_in_db
            if file_to_delete_path.exists():
                try:
                    os.remove(file_to_delete_path)
                except Exception as e:
                    print(f"Error deleting file: {e}")
                    
    # DB에서 게시물 삭제
    result = db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    
    if result.rowcount > 0:
        log_action(action='POST_DELETED', user_id=g.user.get('id', '익명'), post_id=post_id)
        flash('활동 기록이 성공적으로 삭제되었습니다.', 'success')
    else:
        flash('삭제할 글을 찾을 수 없습니다.', 'error')

    return redirect(url_for('index'))

# 6. 댓글 추가 로직 (DB가 없으므로 임시 플래시 메시지 유지)
@app.route('/post/<int:post_id>/comment', methods=['POST'])
@check_banned
def add_comment(post_id):
    # 비로그인 사용자도 댓글을 달 수 있다고 가정
    
    db = get_db()
    post_exists = db.execute("SELECT 1 FROM posts WHERE id = ?", (post_id,)).fetchone()
    
    if post_exists:
        # 로그인 사용자는 ID 사용, 비로그인 사용자는 폼의 username 사용 또는 '익명'
        username = g.user.get('id') if g.user else request.form.get('username') or '익명' 
        content = request.form.get('content')
        
        if content:
            # XSS 방지를 위해 실제 DB에 저장 시에는 HTML 태그를 제거하는 sanitize 함수를 적용해야 함
            
            print(f"Post {post_id}에 댓글 추가 (임시): {username}: {content}")
            flash('댓글이 성공적으로 등록되었습니다. (DB 미적용)', 'success')
            
            log_action(action='COMMENT_ADDED', user_id=username, post_id=post_id, details=content[:50])
        else:
            flash('댓글 내용을 입력해 주세요.', 'error')
    else:
        flash('댓글을 달 글을 찾을 수 없습니다.', 'error')

    return redirect(url_for('detail', post_id=post_id))

# 7. 동아리 멤버 로그인 페이지 및 처리
@app.route('/member_login', methods=['GET', 'POST'])
def member_login():
    if g.user:
        flash(f"{g.user['id']}님은 이미 로그인 상태입니다.", 'info')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        user_id = request.form.get('student_id')
        user_pw = request.form.get('password')
        
        db = get_db()
        user = db.execute(
            "SELECT id, password, is_member, is_banned FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if user and check_password_hash(user['password'], user_pw) and user['is_member']:
            
            if user['is_banned']:
                log_action(action='LOGIN_BANNED', user_id=user_id, details='정지된 계정 로그인 시도')
                flash('이 계정은 관리자에 의해 정지되었습니다.', 'error')
                return render_template('member_login.html')
            
            session['user_id'] = user['id']
            log_action(action='LOGIN_SUCCESS', user_id=user_id)
            flash('동아리 멤버로 로그인되었습니다.', 'success')
            return redirect(url_for('index'))
        else:
            log_action(action='LOGIN_FAILED', user_id=user_id, details='아이디/비밀번호 불일치 또는 비멤버')
            flash('아이디 또는 비밀번호가 잘못되었거나 동아리 멤버가 아닙니다.', 'error')

    return render_template('member_login.html')
    
# 8. 로그아웃
@app.route('/logout')
@login_required
def logout():
    user_id = g.user.get('id', '익명') # g.user에서 ID 가져오기
    session.pop('user_id', None)
    log_action(action='LOGOUT', user_id=user_id)
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

# 9. 일반 사용자 로그인 (미사용 라우트, 템플릿만 존재)
@app.route('/login')
def login():
    return render_template('login.html')

# 10. 동아리원 가입 신청 페이지 및 처리 (submit_application)
@app.route('/member_register', methods=['GET', 'POST'])
def submit_application():
    if g.user and g.user.get('is_member'):
        flash('이미 동아리 멤버로 로그인되어 있습니다.', 'info')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        name = request.form.get('name')
        
        if not student_id or not name:
            flash('학번과 이름을 모두 입력해 주세요.', 'error')
            return redirect(url_for('submit_application'))

        db = get_db()
        try:
            # 학번(student_id)이 users 테이블에 이미 존재하는지 먼저 확인
            existing_user = db.execute("SELECT id FROM users WHERE id = ?", (student_id,)).fetchone()
            if existing_user:
                flash('이미 등록된 멤버입니다. 로그인해 주세요.', 'error')
                return redirect(url_for('member_login'))
                
            db.execute("INSERT INTO member_applications (student_id, name, applied_at) VALUES (?, ?, ?)", 
                       (student_id, name, datetime.now(timezone.utc).isoformat()))
            db.commit()
            
            log_action('MEMBER_APPLY', user_id=student_id, details=f"신청 이름: {name}")
            flash('동아리 멤버 가입 신청이 완료되었습니다. 관리자 승인을 기다려 주세요.', 'success')
            return redirect(url_for('member_login'))
        except sqlite3.IntegrityError:
            # member_applications 테이블에서 UNIQUE 제약 조건 위반 (이미 신청 대기 중)
            flash('이미 신청했거나 사용 중인 학번입니다.', 'error')
            return redirect(url_for('submit_application'))
        except Exception as e:
            db.rollback()
            flash(f'신청 중 오류가 발생했습니다: {e}', 'error')
            return redirect(url_for('submit_application'))
    
    return render_template('member_register.html')


# 11. 일반 사용자 회원가입 페이지 (general_register)
@app.route('/general_register')
def general_register():
    flash('현재 일반 사용자 회원가입은 지원하지 않습니다. 모든 활동 기록은 로그인 없이 열람 가능합니다.', 'warning')
    return redirect(url_for('login'))

# 12. 관리자 대시보드 페이지 (admin_dashboard.html)
@app.route('/admin')
@admin_required
def admin_dashboard():
    
    db = get_db()
    
    applications = db.execute(
        "SELECT id, student_id, name, applied_at FROM member_applications ORDER BY applied_at ASC"
    ).fetchall()

    audit_logs = db.execute(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()
    
    users = db.execute(
        "SELECT id, is_member, is_banned FROM users ORDER BY id ASC"
    ).fetchall()
    
    reports = db.execute(
        "SELECT * FROM report_logs WHERE processed = 0 ORDER BY reported_at ASC"
    ).fetchall()
    
    post_count = db.execute("SELECT COUNT(id) FROM posts").fetchone()[0]
    
    return render_template('admin_dashboard.html', 
                           logs=audit_logs,
                           users=users,
                           post_count=post_count,
                           applications=applications,
                           reports=reports)


# 13. 가입 신청 거절 라우트
@app.route('/reject_application/<int:app_id>', methods=['POST'])
@admin_required
def reject_application(app_id):
    db = get_db()
    
    application = db.execute("SELECT * FROM member_applications WHERE id = ?", (app_id,)).fetchone()
    if not application:
        flash('존재하지 않는 가입 신청입니다.', 'error')
        return redirect(url_for('admin_dashboard'))

    db.execute("DELETE FROM member_applications WHERE id = ?", (app_id,))
    db.commit()
    log_action('MEMBER_REJECT', user_id=g.user.get('id'), details=f"신청 ID: {app_id}, 학번: {application['student_id']}, 이름: {application['name']}")
    flash(f"{application['name']}님의 가입 신청이 거절되었습니다.", 'success')
    return redirect(url_for('admin_dashboard'))

# 14. ID/PW 설정 및 최종 멤버 승인 라우트
@app.route('/finalize_member/<int:app_id>', methods=['GET', 'POST'])
@admin_required
def finalize_member(app_id):
    db = get_db()
    application = db.execute("SELECT * FROM member_applications WHERE id = ?", (app_id,)).fetchone()

    if not application:
        flash('존재하지 않는 가입 신청입니다.', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        member_id = request.form.get('member_id')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not (member_id and password and confirm_password):
            flash('모든 필드를 입력해 주세요.', 'error')
            return render_template('finalize_member.html', application=application)
        
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return render_template('finalize_member.html', application=application)

        # 1. 사용자 ID 중복 확인
        existing_user = db.execute("SELECT id FROM users WHERE id = ?", (member_id,)).fetchone()
        if existing_user:
            flash(f"아이디 '{member_id}'는 이미 사용 중입니다. 다른 아이디를 사용해 주세요.", 'error')
            return render_template('finalize_member.html', application=application)

        try:
            # 2. 새로운 멤버 계정 생성 (is_member=1, is_banned=0, 비밀번호 해시 적용)
            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (id, password, is_member) VALUES (?, ?, ?)", 
                       (member_id, hashed_password, 1))
            
            # 3. 신청 목록에서 해당 신청 삭제
            db.execute("DELETE FROM member_applications WHERE id = ?", (app_id,))
            db.commit()
            
            log_action('MEMBER_ACCEPT', user_id=g.user.get('id'), details=f"신규 ID: {member_id}, 신청자: {application['name']}")
            flash(f"멤버 '{application['name']}'에게 아이디 '{member_id}'가 성공적으로 부여되었습니다. 계정을 전달해 주세요.", 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            db.rollback()
            flash(f"계정 생성 중 오류가 발생했습니다: {e}", 'error')
            return render_template('finalize_member.html', application=application)

    return render_template('finalize_member.html', application=application)

# 15. 게시물/댓글 신고 접수 라우트 (임시 댓글 신고로 가정)
@app.route('/report_item/<int:post_id>', methods=['POST'])
@check_banned
def report_item(post_id):
    reporter_id = g.user.get('id', '비로그인')
    reported_content = request.form.get('reported_content', '내용 확인 필요')
    reason = request.form.get('reason')
    
    if not reason:
        flash('신고 사유를 입력해 주세요.', 'error')
        return redirect(url_for('detail', post_id=post_id))

    db = get_db()
    
    # 신고 내용의 길이를 제한하여 DB에 저장 (오버플로우 방지)
    db.execute("""
        INSERT INTO report_logs (reporter_id, reported_type, reported_id, reported_content, reason, reported_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (reporter_id, 'COMMENT(Post ID)', post_id, reported_content[:255], reason, datetime.now(timezone.utc).isoformat()))
    db.commit()
    
    log_action('ITEM_REPORTED', user_id=reporter_id, post_id=post_id, details=f"사유: {reason}")
    flash('신고가 접수되었습니다. 관리자 확인 후 처리됩니다.', 'success')
    
    return redirect(url_for('detail', post_id=post_id))

# 16. 사용자 밴 (정지) 라우트
@app.route('/ban_user/<user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    if user_id == g.user.get('id'):
        flash('자기 자신은 정지시킬 수 없습니다.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if user_id == 'makerspace_jj':
        flash('최상위 관리자 계정은 정지시킬 수 없습니다.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db = get_db()
    db.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (user_id,))
    db.commit()
    
    log_action('USER_BANNED', user_id=g.user.get('id'), details=f"밴 처리된 사용자: {user_id}")
    flash(f"사용자 '{user_id}' 계정이 정지되었습니다. 로그아웃 후 재로그인 시 접근이 제한됩니다.", 'success')
    return redirect(url_for('admin_dashboard'))

# 17. 사용자 밴 해제 (정지 해제) 라우트
@app.route('/unban_user/<user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
    db.commit()
    
    log_action('USER_UNBANNED', user_id=g.user.get('id'), details=f"정지 해제된 사용자: {user_id}")
    flash(f"사용자 '{user_id}' 계정이 정지 해제되었습니다.", 'success')
    return redirect(url_for('admin_dashboard'))

# 18. 신고 처리 완료 라우트
@app.route('/process_report/<int:report_id>', methods=['POST'])
@admin_required
def process_report(report_id):
    db = get_db()
    db.execute("UPDATE report_logs SET processed = 1 WHERE id = ?", (report_id,))
    db.commit()
    
    log_action('REPORT_PROCESSED', user_id=g.user.get('id'), details=f"신고 처리 완료. ID: {report_id}")
    flash(f"신고 ID {report_id}가 처리 완료 상태로 변경되었습니다.", 'info')
    return redirect(url_for('admin_dashboard'))


# =================================================================
# 앱 실행
# =================================================================
if __name__ == '__main__':
    print(f"Flask 시작. 기본 인코딩: {sys.getdefaultencoding()}, stdout 인코딩: {sys.stdout.encoding}")
    # 릴리스 환경에서는 debug=True 사용 지양
    app.run(debug=True)