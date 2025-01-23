# assetbot.py

from flask import Flask
import logging

assetbot = Flask(__name__)
assetbot.config['DEBUG'] = True

# Load configurations
assetbot.config.from_object('config.Config')

# Configure logging
logging.basicConfig(
    filename='logs/assetbot.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

# Register Blueprints
from blueprints.main import main_bp
assetbot.register_blueprint(main_bp)


# Additional blueprints can be registered here
