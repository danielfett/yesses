import logging


ALERT_LOW = 31
ALERT_MEDIUM = 41
ALERT_HIGH = 51
ALERT_VERY_HIGH = 52

logging.addLevelName(ALERT_LOW, 'ALERT_LOW')
logging.addLevelName(ALERT_MEDIUM, 'ALERT_MEDIUM')
logging.addLevelName(ALERT_HIGH, 'ALERT_HIGH')
logging.addLevelName(ALERT_VERY_HIGH, 'ALERT_VERY_HIGH')

mapping = {
    'low': ALERT_LOW,
    'medium': ALERT_MEDIUM,
    'high': ALERT_HIGH,
    'very high': ALERT_VERY_HIGH,
}
