import logging
import os

if not os.path.exists("logs"):
    os.mkdir("logs")

allowed_logger = logging.getLogger('allowed')
blocked_logger = logging.getLogger('blocked')
attacks_logger = logging.getLogger('attacks')

def setup_loggers():
    logging.basicConfig(level=logging.INFO)

    fh1 = logging.FileHandler('logs/allowed.log')
    fh2 = logging.FileHandler('logs/blocked.log')
    fh3 = logging.FileHandler('logs/attacks.log')

    allowed_logger.addHandler(fh1)
    blocked_logger.addHandler(fh2)
    attacks_logger.addHandler(fh3)

def log_allowed(packet_info):
    allowed_logger.info(f"Allowed: {packet_info}")

def log_blocked(packet_info):
    blocked_logger.warning(f"Blocked: {packet_info}")

def log_attack(msg):
    attacks_logger.error(f"Attack: {msg}")
