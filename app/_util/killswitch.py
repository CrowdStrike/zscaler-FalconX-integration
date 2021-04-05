class Killswitch():
    def __init__(self):
        self.kill = False
        self.fail_streak = 0
    
    def fail(self):
        self.fail_streak = self.fail_streak + 1
        if self.fail_streak >= 10:
            self.kill = True
    
    def succeed(self):
        self.fail_streak = 0