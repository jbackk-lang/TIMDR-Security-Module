import numpy as np
from timdr_rhythm import TIMDRRhythm

# Symulacja telemetrii sieciowej jednego hosta: normalny szum ruchu
# (bytes, w setkach/tysiecach) + malware beaconing do C2 co 15 probek
# (connections, skala 0/1 - ostre impulsy).
rng = np.random.default_rng(0)
n = 300
t = np.arange(n)

bytes_in = rng.normal(1000, 300, n)                      # szum tla, duza skala
connections = (np.sin(2 * np.pi * t / 15) > 0.9).astype(float)  # beacon co 15 probek

X = np.column_stack([bytes_in, connections])

r = TIMDRRhythm(max_lag=60, min_period=3, power_thresh=0.4)
periods, score = r.beacon_score(X)

print("Wykryte okresy (lag_probek, moc 0..1):", periods)
print("Najsilniejszy rytm (beacon_score):", round(score, 3))
top_lag = max(periods, key=lambda p: p[1])[0] if periods else None
print("Dominujacy okres:", top_lag, "probek",
      "-> poprawnie wykryty prawdziwy beacon (15)" if top_lag == 15 else "")
