from scipy.stats import beta

from .brs import TrustModel as ModelBase

class TrustModel(ModelBase):
    def __init__(self, forgetting_factor):
        super().__init__()

        if forgetting_factor < 0 or forgetting_factor > 1:
            raise RuntimeError(f"Forgetting Factor {forgetting_factor} is out of valid range")

        self.forgetting_factor = forgetting_factor

    def update_with_observation(self, observation):
        if observation.good:
            self.alpha = self.forgetting_factor * self.alpha + 1
        else:
            self.beta = self.forgetting_factor * self.beta + 1
