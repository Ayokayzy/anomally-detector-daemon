class Notifier:
    def __init__(self, config):
        self.config = config

    def send_ban_alert(self, ip, condition, rate, mean, duration):
        pass

    def send_unban_alert(self, ip, ban_count, duration):
        pass

    def send_global_alert(self, condition, rate, mean):
        pass