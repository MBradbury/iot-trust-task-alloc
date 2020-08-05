from scipy.stats import beta

class TrustModel:
    def __init__(self):
        self.alpha = None
        self.beta = None

    def initialise(self, alpha=1, beta=1):
        self.alpha = alpha
        self.beta = beta

    def update_with_observation(self, observation):
        if observation.good:
            self.alpha += 1
        else:
            self.beta += 1

    def estimate_trust(self):
        return (beta.mean(self.alpha, self.beta), beta.std(self.alpha, self.beta))
