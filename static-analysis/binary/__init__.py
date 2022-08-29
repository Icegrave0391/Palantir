from .loader import Loader
from .elfloader import ELFLoader

import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

loaders = [elfloader]

# def get_loader():