from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
import os

app = Flask(__name__)

# 用于连接数据的数据库
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:080305@127.0.0.1:3306/movie'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['REDIS_URL'] = 'redis://127.0.0.1:6379/0'
app.config['SECRET_KEY'] = 'zwm_movie'
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads/admin/')
app.config['FC_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads/users/')
app.debug = True
db = SQLAlchemy(app)
rd = FlaskRedis(app)

# 不要在生成db之前导入注册蓝图。
from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')


@app.errorhandler(404)
def page_not_found(error):
    return render_template('home/404.html'), 404
