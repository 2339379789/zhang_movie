# 唯一标识符
import uuid
import json
import os
from . import home
import datetime
from functools import wraps
from flask import render_template, redirect, url_for, flash, session, request, Response
from app.home.forms import RegistForm, LoginForm, CommentForm, UserdetailForm, PwdForm
from app.models import User, Userlog, Preview, Tag, Movie, Comment, Moviecol
from werkzeug.security import generate_password_hash
from app import db, app, rd
from werkzeug.utils import secure_filename


# 登录装饰器
def user_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('home.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# 登录
@home.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data['name']).first()
        if user:
            if not user.check_pwd(data['pwd']):
                flash('密码错误！', 'err')
                return redirect(url_for('home.login'))
        else:
            flash('账户不存在！', 'err')
            return redirect(url_for('home.login'))
        session['user'] = user.name
        session['user_id'] = user.id
        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.user'))
    return render_template('home/login.html', form=form)


# 退出
@home.route('/logout/')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('home.login'))


# 注册
@home.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash('注册成功！', 'ok')
    return render_template('home/register.html', form=form)


# 用户中心资料修改
@home.route('/user/', methods=['GET', 'POST'])
@user_login_req
def user():
    form = UserdetailForm()
    user = User.query.get(int(session['user_id']))
    form.face.validators = []
    if request.method == 'GET':
        # 第一次访问时，显示之前的数据
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        if form.face.data != '':
            file_face = secure_filename(form.face.data.filename)
            if not os.path.exists(app.config['FC_DIR']):
                os.makedirs(app.config['FC_DIR'])
                os.chmod(app.config['FC_DIR'])
            user.face = change_filename(file_face)
            # 将表单中的图片数据保存到配置路径中
            form.face.data.save(app.config['FC_DIR'] + user.face)
        name_count = User.query.filter_by(name=data['name']).count()
        if data['name'] != user.name and name_count == 1:
            flash('昵称已经存在!', 'err')
            return redirect(url_for('home.user'))
        email_count = User.query.filter_by(email=data['email']).count()
        if data['email'] != user.email and email_count == 1:
            flash('邮箱已经存在!', 'err')
            return redirect(url_for('home.user'))
        phone_count = User.query.filter_by(phone=data['phone']).count()
        if data['phone'] != user.phone and phone_count == 1:
            flash('手机已经存在!', 'err')
            return redirect(url_for('home.user'))
        # 保存
        user.name = data['name']
        user.email = data['email']
        user.phone = data['phone']
        user.info = data['info']
        db.session.add(user)
        db.session.commit()
        flash('修改成功!', 'ok')
        return redirect(url_for('home.user'))
    return render_template('home/user.html', form=form, user=user)


# 修改密码
@home.route('/pwd/', methods=['GET', 'PSOT'])
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session['user']).first()
        if not user.check_pwd(data['pwd']):
            flash('旧密码错误！', 'err')
            return redirect(url_for('home.pwd'))
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('修改密码成功，请重新登录！', 'ok')
        return redirect(url_for('home.logout'))
    return render_template('home/pwd.html', form=form)


# 评论列表
@home.route('/comments/<int:page>/')
def comments(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == session['user_id']
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('home/comments.html', page_data=page_data)


# 登录日志列表
@home.route('/loginlog/<int:page>/')
def loginlog(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.filter_by(
        user_id=int(session['user_id'])
    ).order_by(Userlog.addtime.desc()).paginate(page=page, per_page=2)
    return render_template('home/loginlog.html', page_data=page_data)


# 电影收藏列表
@home.route('/moviecol/<int:page>/')
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(
        Movie.id == Moviecol.movie_id,
        User.id == session['user_id']
    ).order_by(Moviecol.addtime.desc()).paginate(page=page, per_page=2)
    return render_template('home/moviecol.html', page_data=page_data)


# 添加收藏
@home.route('/moviecol/add/')
@user_login_req
def moviecol_add():
    uid = request.args.get('uid', '')
    mid = request.args.get('mid', '')
    moviecol = Moviecol.query.filter_by(
        user_id=int(uid),
        movie_id=int(mid)
    ).count()
    # 已经收藏过
    if moviecol == 1:
        data = dict(ok=0)
    # 未收藏进行收藏
    if moviecol == 0:
        moviecol = Moviecol(
            user_id=int(uid),
            movie_id=int(mid)
        )
        db.session.add(moviecol)
        db.session.commit()
        data = dict(ok=1)
    return json.dumps(data)


# 电影首页
@home.route('/<int:page>/')
@home.route('/')
def index(page=None):
    tags = Tag.query.all()
    page_data = Movie.query
    # 获取页面请求的标签参数筛选
    tid = request.args.get('tid', 0)
    if int(tid) != 0:
        page_data = page_data.filter_by(tag_id=int(tid))
    # 获取页面请求的星级参数筛选
    star = request.args.get('star', 0)
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))
    # 获取页面请求的时间参数排序
    time = request.args.get('time', 0)
    if int(time) != 0:
        if int(time) == 1:
            page_data = page_data.order_by(Movie.release_time.desc())
        else:
            page_data = page_data.order_by(Movie.release_time.asc())
    # 获取页面请求的播放量参数排序
    pm = request.args.get('pm', 0)
    if int(pm) != 0:
        if int(pm) == 1:
            page_data = page_data.order_by(
                Movie.playnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.playnum.asc()
            )
    # 获取页面请求的评论量参数排序
    cm = request.args.get('cm', 0)
    if int(cm) != 0:
        if int(cm) == 1:
            page_data = page_data.order_by(
                Movie.commentnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.commentnum.asc()
            )
    if page is None:
        page = 1
    page_data = page_data.paginate(page=page, per_page=8)
    # 首次访问需要的初始值传给页面，以字典的形式
    p = dict(tid=tid, star=star, time=time, pm=pm, cm=cm)
    return render_template('home/index.html', tags=tags, p=p, page_data=page_data)


# 首页轮播
@home.route('/animation/')
def animation():
    data = Preview.query.all()
    for i in data:
        i.id = i.id - 1
    return render_template('home/animation.html', data=data)


# 搜索
@home.route('/search/<int:page>/')
def search(page=None):
    if page is None:
        page = 1
    key = request.args.get('key', '')
    movie_count = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).count()
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    # 点击分页时时保留关键字
    page_data.key = key
    return render_template('home/search.html', movie_count=movie_count, key=key, page_data=page_data)


# 电影详情播放
@home.route('/play/<int:id>/<int:page>/', methods=['GET', 'POST'])
def play(id=None, page=None):
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    form = CommentForm()
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=movie.id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        db.session.add(movie)
        db.session.commit()
        flash('添加评论成功！', 'ok')
        return redirect(url_for('home.play', id=movie.id, page=1))
    movie.playnum = movie.playnum + 1
    db.session.add(movie)
    db.session.commit()
    return render_template('home/play.html', form=form, movie=movie, page_data=page_data)


# 弹幕播放
@home.route('/video/<int:id>/<int:page>/', methods=['GET', 'POST'])
def video(id=None, page=None):
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)

    movie.playnum = movie.playnum + 1
    form = CommentForm()
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=movie.id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        db.session.add(movie)
        db.session.commit()
        flash('添加评论成功！', 'ok')
        return redirect(url_for('home.video', id=movie.id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template('home/video.html', movie=movie, form=form, page_data=page_data)


# redis消息队列实现弹幕
@home.route('/tm/', methods=['GET', 'POST'])
def tm():
    import json
    if request.method == 'GET':
        # 获取弹幕消息队列
        id = request.args.get('id')
        # 存放在redis队列中的键值
        key = 'movie' + str(id)
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            res = {
                'code': 1,
                'danmaku': [json.loads(v) for v in msgs]
            }
        else:
            res = {
                'code': 1,
                'danmaku': []
            }
        resp = json.dumps(res)
    if request.method == 'POST':
        # 添加弹幕
        data = json.loads(request.get_data())
        msg = {
            '__v': 0,
            'author': data['author'],
            'time': data['time'],
            'text': data['text'],
            'color': data['color'],
            'type': data['type'],
            'ip': request.remote_addr,
            '_id': datetime.datetime.now().strftime('%Y%m%d%H%M%S') + uuid.uuid4().hex,
            'player': [
                data['player']
            ]
        }
        res = {
            'code': 1,
            'data': msg
        }
        resp = json.dumps(res)
        # 将添加的弹幕推入redis的队列中
        rd.lpush('movie' + str(data['player']), json.dumps(msg))
    return Response(resp, mimetype='application/json')


# 修改上传的文件名的函数
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + \
               str(uuid.uuid4().hex) + fileinfo[-1]
    return filename
