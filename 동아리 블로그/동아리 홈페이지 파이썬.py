# -*- coding: utf-8 -*-
import sys
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from datetime import datetime

# =================================================================
# [필수 수정: UnicodeEncodeError 방지]
# 파이썬의 표준 입출력 스트림이 UTF-8 인코딩을 사용하도록 강제합니다.
# 이 코드가 문제를 해결하지 못하면, 실행 환경(터미널) 자체의 설정을 UTF-8로 변경해야 합니다.
try:
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
    if sys.stderr.encoding != 'utf-8':
        sys.stderr = open(sys.stderr.fileno(), mode='w', encoding='utf-8', buffering=1)
except Exception:
    # 예외 발생 시 (예: 파일 디스크립터가 없는 환경) 무시
    pass
# =================================================================

# Flask 앱 설정
app = Flask(__name__)
# 보안을 위해 실제 배포 시에는 복잡하고 긴 문자열로 변경해야 합니다.
app.secret_key = '전주공고_메이커스페이스_임시_시크릿키_2025'

# 임시 데이터베이스 역할 (실제 DB 연결 시 이 부분은 삭제해야 합니다)
posts_db = [
    {'id': 1, 'title': '첫 번째 활동 기록: 3D 프린팅', 'content': '메이커 스페이스 첫 프로젝트를 시작했습니다. 3D 프린팅 연습 중입니다.', 'author': '김메이커', 'created_at': datetime(2025, 10, 20, 14, 30)},
    {'id': 2, 'title': '회로 설계 및 테스트 완료', 'content': '아두이노를 이용한 센서 회로를 설계하고 작동 테스트를 완료했습니다.', 'author': '박스페이스', 'created_at': datetime(2025, 10, 25, 9, 0)}
]

# 임시 사용자 (로그인 시뮬레이션용)
MEMBER_ID = "makerspace_jj"
MEMBER_PW = "1234"

# 템플릿 렌더링 전에 실행되어 모든 템플릿에서 g.user를 사용할 수 있게 합니다.
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id == MEMBER_ID:
        g.user = {'id': user_id, 'is_member': True}
    elif user_id:
        # 일반 사용자는 is_member=False로 처리 (현재는 일반 로그인 미지원으로 단순히 user_id만 확인)
        g.user = {'id': user_id, 'is_member': False}
        
# =================================================================
# 라우팅 및 기능 구현
# =================================================================

# 1. 메인 페이지 (index.html)
@app.route('/')
def index():
    # 최신 글이 먼저 보이도록 역순으로 정렬
    sorted_posts = sorted(posts_db, key=lambda x: x['created_at'], reverse=True)
    # index.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('index.html', posts=sorted_posts)

# 2. 글 작성 페이지 (write.html)
@app.route('/write', methods=['GET', 'POST'])
def write():
    # 동아리 멤버가 아니면 접근 거부
    if not (g.user and g.user.get('is_member')):
        flash('활동 기록은 동아리 멤버만 작성할 수 있습니다.', 'warning')
        return redirect(url_for('member_login'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        author = request.form.get('author') or g.user.get('id', '익명')
        
        # 입력값 검증 (간단하게)
        if not title or not content:
            flash('제목과 내용을 모두 입력해 주세요.', 'error')
            # write.html 템플릿은 별도로 제공되어야 합니다.
            return render_template('write.html')
            
        # 새 글 ID 생성
        new_id = max(post['id'] for post in posts_db) + 1 if posts_db else 1
        
        new_post = {
            'id': new_id, 
            'title': title, 
            'content': content, 
            'author': author, 
            'created_at': datetime.now()
        }
        
        posts_db.append(new_post) 
        
        flash('새로운 활동 기록이 성공적으로 작성되었습니다.', 'success')
        # detail 엔드포인트로 리디렉션
        return redirect(url_for('detail', post_id=new_id))
    
    # write.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('write.html')

# 3. 상세 보기 페이지 (detail.html)
@app.route('/post/<int:post_id>')
def detail(post_id):
    post = next((p for p in posts_db if p['id'] == post_id), None)
    
    if not post:
        flash('요청하신 글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))

    # 임시 댓글 데이터 (실제 DB 연결 시 이 부분은 삭제해야 합니다)
    comments = [
        {'username': '방문자1', 'content': '좋은 활동이네요!', 'created_at': datetime.now()},
    ]
        
    # detail.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('detail.html', post=post, comments=comments)

# 4. 글 수정 페이지 (edit.html)
@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
def edit(post_id):
    # 동아리 멤버가 아니면 접근 거부
    if not (g.user and g.user.get('is_member')):
        flash('수정 권한이 없습니다.', 'warning')
        return redirect(url_for('detail', post_id=post_id))

    post = next((p for p in posts_db if p['id'] == post_id), None)
    if not post:
        flash('요청하신 글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        post['title'] = request.form.get('title')
        post['content'] = request.form.get('content')
        
        flash('활동 기록이 성공적으로 수정되었습니다.', 'success')
        return redirect(url_for('detail', post_id=post_id))
        
    # edit.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('edit.html', post=post)

# 5. 글 삭제 로직
@app.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    # 동아리 멤버가 아니면 접근 거부
    if not (g.user and g.user.get('is_member')):
        flash('삭제 권한이 없습니다.', 'warning')
        return redirect(url_for('detail', post_id=post_id))
        
    global posts_db
    post_index = next((i for i, p in enumerate(posts_db) if p['id'] == post_id), None)
    
    if post_index is not None:
        posts_db.pop(post_index)
        flash('활동 기록이 성공적으로 삭제되었습니다.', 'success')
    else:
        flash('삭제할 글을 찾을 수 없습니다.', 'error')

    return redirect(url_for('index'))

# 6. 댓글 추가 로직 (detail.html에 댓글 폼이 있을 때 필요)
@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    # 이 부분은 실제 댓글 DB가 없으므로 임시 플래시 메시지만 보냅니다.
    post = next((p for p in posts_db if p['id'] == post_id), None)
    
    if post:
        # g.user가 있으면 그 ID를, 없으면 폼에서 받은 이름을 사용
        username = g.user.get('id', request.form.get('username') or '익명') 
        content = request.form.get('content')
        
        if content:
            # 실제 DB에서는 여기에 댓글 저장 로직을 추가해야 합니다.
            print(f"Post {post_id}에 댓글 추가: {username}: {content}")
            flash('댓글이 성공적으로 등록되었습니다.', 'success')
        else:
            flash('댓글 내용을 입력해 주세요.', 'error')
    else:
        flash('댓글을 달 글을 찾을 수 없습니다.', 'error')

    return redirect(url_for('detail', post_id=post_id))
    
# 7. 동아리 멤버 로그인 페이지 및 처리
@app.route('/member_login', methods=['GET', 'POST'])
def member_login():
    if request.method == 'POST':
        # **********************************************
        # [수정] HTML 폼의 'name="student_id"'에 맞게 변경
        # **********************************************
        user_id = request.form.get('student_id')
        user_pw = request.form.get('password')
        
        # 임시 ID/PW 비교
        if user_id == MEMBER_ID and user_pw == MEMBER_PW:
            session['user_id'] = MEMBER_ID
            flash('동아리 멤버로 로그인되었습니다.', 'success')
            return redirect(url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 잘못되었습니다.', 'error')

    return render_template('member_login.html')
    
# 8. 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.', 'info')
    return redirect(url_for('index'))

# 9. 일반 사용자 로그인 (미사용 라우트, 템플릿만 존재)
# 이 라우트는 일반 사용자 접근 안내를 위한 'login.html'을 렌더링합니다.
@app.route('/login')
def login():
    # login.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('login.html')

# 10. 동아리원 회원가입 페이지 (member_register.html)
@app.route('/member_register')
def member_register():
    # member_register.html 템플릿은 별도로 제공되어야 합니다.
    return render_template('member_register.html')

# 11. 일반 사용자 회원가입 페이지 (general_register)
@app.route('/general_register')
def general_register():
    flash('현재 일반 사용자 회원가입은 지원하지 않습니다. 모든 활동 기록은 로그인 없이 열람 가능합니다.', 'warning')
    return redirect(url_for('login'))
    
# =================================================================
# 앱 실행
# =================================================================
if __name__ == '__main__':
    # Flask 앱 실행 시 인코딩이 UTF-8로 설정되었는지 확인하는 로그 (오류 방지용)
    print(f"Flask 시작. 기본 인코딩: {sys.getdefaultencoding()}, stdout 인코딩: {sys.stdout.encoding}")
    # 디버그 모드는 개발 단계에서만 True로 설정하세요.
    app.run(debug=True)