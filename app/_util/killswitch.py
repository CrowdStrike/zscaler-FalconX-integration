# This class provides utility functions to monitor and respond to runtime errors
# Since this integration was written to run indefinitely, edge cases can throw the app into an endless loop of errors
# Killswitch causes the app to terminate after an arbitrary number of failures
class Killswitch():
    def __init__(self):
        self.kill = False
        self.fail_streak = 0  # fail streak initialized at zero
        self.max_streak = 10  # maximum number of failures in a row until forced exit

    # called when an error propogates to main.py
    def fail(self):
        self.fail_streak = self.fail_streak + 1  # increment failed runs
        if self.fail_streak >= self.max_streak:  # check if condition met to activate killswitch
            self.kill = True  # killswitch activated if condition met

    # called at the end of a successful loop in app/integration.py
    def succeed(self):
        self.fail_streak = 0

    # streak getter
    def get_streak(self):
        return self.fail_streak

    # max_streak getter
    def get_max_streak(self):
        return self.max_streak

    # called to check if forced exit condition met
    def activated(self):
        return self.kill
