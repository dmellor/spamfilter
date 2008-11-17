import logging
from logging.handlers import SysLogHandler

handler = SysLogHandler('/dev/log', SysLogHandler.LOG_MAIL)
handler.setFormatter(logging.Formatter('%(message)s'))
root = logging.getLogger()
root.setLevel(logging.INFO)
root.addHandler(handler)

__all__ = []
