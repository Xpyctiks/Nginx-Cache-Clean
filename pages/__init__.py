from flask import Blueprint
from .admin_panel import admin_panel_bp
from .login import login_bp
from .logout import logout_bp
from .root import root_bp

blueprint = Blueprint("main", __name__)
blueprint.register_blueprint(admin_panel_bp)
blueprint.register_blueprint(login_bp)
blueprint.register_blueprint(logout_bp)
blueprint.register_blueprint(root_bp)
