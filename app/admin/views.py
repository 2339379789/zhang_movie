import os
import uuid
from datetime import datetime
from app import db, app
from functools import wraps
from . import admin
from flask import render_template, redirect, url_for, flash, session, request, g, abort
from app.admin.forms import LoginForm, TagForm, MovieFrom, PreviewForm, PwdForm, RoleForm, AuthForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Auth, Role
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash


def admin_login_req(f):
    """
    登录装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_auth(f):
    """
    权限控制装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(Role).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id']
        ).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(',')))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if str(rule) not in urls:
            abort(404)
        return f(*args, **kwargs)

    return decorated_function


@admin.context_processor
def tpl_extra():
    """
    上下文处理器：定义全局变量，提供给模板使用
    """
    try:
        admin = Admin.query.filter_by(name=session['admin']).first()
    except:
        admin = None
    data = dict(
        online_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        logo='mingzai.jpg',
        admin=admin,
    )
    # 之后直接传个admin。取admin face字段即可
    return data


@admin.route('/')
@admin_login_req
def index():
    """
    后台首页系统管理
    """
    g.logo = 'mtianyan.jpg'
    return render_template('admin/index.html')


@admin.route('/admin/add/', methods=['GET', 'POST'])
def admin_add():
    """
    添加管理员（管理员注册）
    """
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role_id'],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash('添加管理员成功！', 'ok')
    return render_template('admin/admin_add.html', form=form)


@admin.route("/admin/list/<int:page>/", methods=["GET"])
@admin_login_req
# @admin_auth
def admin_list(page=None):
    """
    管理员列表
    """
    if page is None:
        page = 1
    page_data = Admin.query.join(Role).filter(
        Role.id == Admin.role_id
    ).order_by(Admin.addtime.desc()).paginate(page=page, per_page=1)
    return render_template("admin/admin_list.html", page_data=page_data)


@admin.route('/login/', methods=['GET', 'POST'])
def login():
    """
    后台登录
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash('密码错误！', 'err')
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        # 保存管理员登录日志
        adminlog = Adminlog(admin_id=admin.id, ip=request.remote_addr)
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    """
    后台退出
    """
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd/', methods=['GET', 'POST'])
@admin_login_req
def pwd():
    """
    管理员密码修改
    """
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功，请重新登录！', 'ok')
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


@admin.route('/tag/add/', methods=['GET', 'POST'])
@admin_login_req
def tag_add():
    """
    添加标签
    """
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        if tag == 1:
            flash('标签已存在', 'err')
            return redirect(url_for('admin.tag_add'))
        tag = Tag(name=data['name'])
        db.session.add(tag)
        db.session.commit()
        # 保存添加标签日志
        oplog = Oplog(admin_id=session['admin_id'],
                      ip=request.remote_addr,
                      reason='添加标签%s' % data['name']
                      )
        db.session.add(oplog)
        db.session.commit()
        flash('标签添加成功', 'ok')
        redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route('/tag/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def tag_edit(id=None):
    """
    标签详情
    """
    form = TagForm()
    form.submit.label.text = '修改'
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        # 说明已经有这个标签了,此时向添加一个与其他标签重名的标签。
        if tag.name != data['name'] and tag_count == 1:
            flash('标签已存在', 'err')
            return redirect(url_for('admin.tag_edit', id=tag.id))
        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash('标签修改成功', 'ok')
        redirect(url_for('admin.tag_edit', id=tag.id))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


@admin.route('/tag/list/<int:page>/')
@admin_login_req
def tag_list(page=None):
    """
    标签列表
    """
    if page is None:
        page = 1
    # 获取当前页的标签，按添加时间倒序，每页显示3个
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=3)
    return render_template('admin/tag_list.html', page_data=page_data)


@admin.route('/tag/del/<int:id>/')
@admin_login_req
def tag_del(id=None):
    """
    标签删除
    """
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('标签<<{0}>>删除成功'.format(tag.name), 'ok')
    return redirect(url_for('admin.tag_list', page=1))


@admin.route('/movie/add/', methods=['GET', 'POST'])
@admin_login_req
def movie_add():
    """
    添加电影
    """
    form = MovieFrom()
    if form.validate_on_submit():
        data = form.data
        # 播放的电影(secure_filename将文件名转换为安全的模式)
        file_url = secure_filename(form.url.data.filename)
        # 电影的封面
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            # 创建一个多级目录
            os.makedirs(app.config['UP_DIR'])

        url = change_filename(file_url)
        logo = change_filename(file_logo)
        # 将修改后的视频、图片名称以地址的形式保存起来（form.字段.data.save(path)）
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        movie = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )
        db.session.add(movie)
        db.session.commit()
        flash('添加电影成功！', 'ok')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


@admin.route('/movie/list/<int:page>/')
@admin_login_req
def movie_list(page=None):
    """
    电影列表
    """
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id == Movie.tag_id).order_by(Movie.addtime.desc()).paginate(page=page,
                                                                                                             per_page=1)
    return render_template('admin/movie_list.html', page_data=page_data)


@admin.route('/movie/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def movie_edit(id=None):
    """
    修改电影
    """
    form = MovieFrom()
    # 将验证设为空（不需要验证）
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash('片名已经存在！', 'err')
            return redirect(url_for('admin.movie_edit', id=id))
        # 创建目录
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        # 上传视频
        if form.url.data != '':
            # 删除原来的视频
            os.remove(os.path.join(app.config['UP_DIR']) + movie.url)
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)
        # 上传图片
        if form.logo.data != '':
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.title = data['title']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']
        db.session.add(movie)
        db.session.commit()
        flash('修改电影成功！', 'ok')
        return redirect(url_for('admin.movie_edit', id=id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


@admin.route('/movie/del/<int:id>/', methods=['GET'])
@admin_login_req
# @admin_auth
def movie_del(id=None):
    """
    电影删除
    """
    movie = Movie.query.get_or_404(id)
    db.session.delete(movie)
    db.session.commit()
    flash('电影删除成功', 'ok')
    return redirect(url_for('admin.movie_list', page=1))


@admin.route('/preview/add/', methods=['GET', 'POST'])
@admin_login_req
def preview_add():
    """
    上映预告添加
    """
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        logo = change_filename(file_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash('添加预告成功！', 'ok')
        return redirect(url_for('admin.preview_add'))
    return render_template('admin/preview_add.html', form=form)


@admin.route('/preview/list/<int:page>/')
@admin_login_req
def preview_list(page=None):
    """
    上映预告列表
    """
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=1)
    return render_template('admin/preview_list.html', page_data=page_data)


@admin.route('/preview/del/<int:id>/')
@admin_login_req
# @admin_auth
def preview_del(id=None):
    """
    预告删除
    """
    preview = Preview.query.get_or_404(id)
    db.session.delete(preview)
    db.session.commit()
    flash('预告删除成功', 'ok')
    return redirect(url_for('admin.preview_list', page=1))


@admin.route('/preview/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
# @admin_auth
def preview_edit(id):
    """
    编辑预告
    """
    form = PreviewForm()
    # 下面这行代码禁用编辑时的提示:封面不能为空
    form.logo.validators = []
    preview = Preview.query.get_or_404(int(id))
    if request.method == 'GET':
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data != '':
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + preview.logo)
        preview.title = data['title']
        db.session.add(preview)
        db.session.commit()
        flash('修改预告成功！', 'ok')
        return redirect(url_for('admin.preview_edit', id=id))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


@admin.route('/user/list/<int:page>/')
@admin_login_req
def user_list(page=None):
    """
    会员列表
    """
    if page is None:
        page = 1
    page_data = User.query.order_by(User.addtime.desc()).paginate(page=page, per_page=3)
    return render_template('admin/user_list.html', page_data=page_data)


@admin.route('/user/view/<int:id>/')
@admin_login_req
def user_view(id=None):
    """
    会员详情
    """
    from_page = request.args.get('fp')
    if not from_page:
        from_page = 1
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_view.html', user=user, from_page=from_page)


@admin.route('/user/del/<int:id>/')
@admin_login_req
def user_del(id=None):
    """
    删除会员
    """
    # 因为删除当前页。假如是最后一页，这一页已经不见了。回不到。
    from_page = int(request.args.get('fp')) - 1
    # 此处考虑全删完了，没法前挪的情况，0被视为false
    if not from_page:
        from_page = 1
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash('删除会员成功！', 'ok')
    return redirect(url_for('admin.user_list', page=from_page))


@admin.route('/comment/list/<int:page>/')
@admin_login_req
def comment_list(page=None):
    """
    评论列表
    """
    if page is None:
        page = 1
    # 通过评论join查询其相关的movie，和相关的用户。
    # 然后过滤出其中电影id等于评论电影id的电影，和用户id等于评论用户id的用户
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=1)
    return render_template('admin/comment_list.html', page_data=page_data)


@admin.route('/comment/del/<int:id>/')
@admin_login_req
def comment_del(id=None):
    """
    删除评论
    """
    # 因为删除当前页。假如是最后一页，这一页已经不见了。回不到。
    from_page = int(request.args.get('fp')) - 1
    # 此处考虑全删完了，没法前挪的情况，0被视为false
    if not from_page:
        from_page = 1
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash('删除评论成功！', 'ok')
    return redirect(url_for('admin.comment_list', page=from_page))


@admin.route('/moviecol/list/<int:page>/')
@admin_login_req
def moviecol_list(page=None):
    """
    电影收藏列表
    """
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(
        Movie.id == Moviecol.movie_id,
        User.id == Moviecol.user_id
    ).order_by(Moviecol.addtime.desc()).paginate(page=page, per_page=1)
    return render_template('admin/moviecol_list.html', page_data=page_data)


@admin.route('/moviecol/del/<int:id>/')
@admin_login_req
# @admin_auth
def moviecol_del(id=None):
    """
    收藏删除
    """
    # 因为删除当前页。假如是最后一页，这一页已经不见了。回不到。
    from_page = int(request.args.get('fp')) - 1
    # 此处考虑全删完了，没法前挪的情况，0被视为false
    if not from_page:
        from_page = 1
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash('删除收藏成功！', 'ok')
    return redirect(url_for('admin.moviecol_list', page=from_page))


@admin.route('/oplog/list/<int:page>/')
@admin_login_req
def oplog_list(page=None):
    """
    操作日志列表
    """
    if page is None:
        page = 1
    page_data = Oplog.query.join(Admin).filter(
        Admin.id == Oplog.admin_id,
    ).order_by(Oplog.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/oplog_list.html', page_data=page_data)


@admin.route('/adminloginlog/list/<int:page>/')
@admin_login_req
def adminloginlog_list(page=None):
    """
    管理员登录日志列表
    """
    if page is None:
        page = 1
    page_data = Adminlog.query.join(Admin).filter(
        Admin.id == Adminlog.admin_id,
    ).order_by(Adminlog.addtime.desc()
               ).paginate(page=page, per_page=1)
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


@admin.route('/userloginlog/list/<int:page>/')
@admin_login_req
def userloginlog_list(page=None):
    """
    会员登录日志列表
    """
    if page is None:
        page = 1
    page_data = Userlog.query.join(User).filter(
        User.id == Userlog.user_id,
    ).order_by(Userlog.addtime.desc()).paginate(page=page, per_page=2)
    return render_template('admin/userloginlog_list.html', page_data=page_data)


@admin.route('/role/add/', methods=['GET', 'POST'])
@admin_login_req
def role_add():
    """
    角色添加
    """
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role.query.filter_by(name=data['name'])
        if role:
            flash("角色已存在！", "err")
            return redirect(url_for("admin.role_add"))
        role = Role(
            name=data['name'],
            auths=','.join(map(lambda v: str(v), data['auths']))
        )
        db.session.add(role)
        db.session.commit()
        flash('添加角色成功！', 'ok')
    return render_template('admin/role_add.html', form=form)


@admin.route('/role/list/<int:page>/')
@admin_login_req
def role_list(page=None):
    """
    角色列表
    """
    if page is None:
        page = 1
    page_data = Role.query.order_by(Role.addtime.desc()).paginate(page=page, per_page=3)
    return render_template('admin/role_list.html', page_data=page_data)


@admin.route('/role/del/<int:id>/')
@admin_login_req
def role_del(id=None):
    """
    角色删除
    """
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash('删除角色成功！', 'ok')
    return redirect(url_for('admin.role_list', page=1))


@admin.route('/role/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def role_edit(id=None):
    """
    编辑角色
    """
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == 'GET':
        auths = role.auths
        form.auths.data = list(map(lambda v: str(v), auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role.name = data['name']
        role.auths = ','.join(map(lambda v: str(v), data['auths']))
        db.session.add(role)
        db.session.commit()
        flash('修改角色成功！', 'ok')
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route('/auth/add/', methods=['GET', 'POST'])
@admin_login_req
# @admin_auth
def auth_add():
    """
    添加权限
    """
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash('添加权限成功！', 'ok')
    return render_template('admin/auth_add.html', form=form)


@admin.route('/auth/list/<int:page>/')
@admin_login_req
# @admin_auth
def auth_list(page=None):
    """
    权限列表
    """
    if page is None:
        page = 1
    page_data = Auth.query.order_by(Auth.addtime.desc()).paginate(page=page, per_page=2)
    return render_template('admin/auth_list.html', page_data=page_data)


@admin.route('/auth/del/<int:id>/')
@admin_login_req
# @admin_auth
def auth_del(id=None):
    """
    权限删除
    """
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash('删除权限成功！', 'ok')
    return redirect(url_for('admin.auth_list', page=1))


@admin.route('/auth/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
# @admin_auth
def auth_edit(id=None):
    """
    编辑权限
    """
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth.url = data['url']
        auth.name = data['name']
        db.session.add(auth)
        db.session.commit()
        flash('修改权限成功！', 'ok')
        redirect(url_for('admin.auth_edit', id=id))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


def change_filename(filename):
    """
    修改文件名称
    """
    fileinfo = os.path.splitext(filename)
    filename = datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename
