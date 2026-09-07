import numpy as np

class TIMDRSecurity:
    def __init__(self):
        pass

    def timdr_flow(self, flow):
        f = np.array(flow)
        metrics = f[:, :3]
        t = f[:, 3]
        v = np.gradient(metrics, t, axis=0)
        a = np.gradient(v, t, axis=0)
        flow_grad = np.gradient(v + a, axis=0)
        return flow_grad

    def twist(self, flow, thresh=0.4):
        f = np.array(flow)
        bytes_in = f[:, 0]
        bytes_out = f[:, 1]
        conns = f[:, 2]
        ratio = bytes_in / (bytes_out + 1e-6)
        dratio = np.gradient(ratio)
        dconns = np.gradient(conns)
        twist_ratio = np.where(np.abs(dratio) > thresh)[0]
        twist_conns = np.where(np.abs(dconns) > np.mean(np.abs(dconns)) * 3)[0]
        return {"ratio_twist": twist_ratio, "connection_twist": twist_conns}

    def trm_reduce(self, flow):
        f = np.array(flow)
        metrics = f[:, :3]
        smooth = metrics.copy()
        for i in range(1, len(metrics)-1):
            smooth[i] = (metrics[i-1] + metrics[i] + metrics[i+1]) / 3.0
        return smooth

    def anomaly_score(self, flow):
        grad = self.timdr_flow(flow)
        score = np.linalg.norm(grad, axis=1)
        return score
