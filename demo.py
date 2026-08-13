from timdr_security import TIMDRSecurity
from timdr_server import TIMDRServer

print("=== TIMDR Security (siec) ===")
sec = TIMDRSecurity()
flow = [
    [1000, 800, 12, 0],
    [1200, 900, 13, 1],
    [1500, 1100, 14, 2],
    [5000, 2000, 40, 3],   # anomalia
    [5200, 2100, 42, 4],
]
print("TIMDR-flow:", sec.timdr_flow(flow))
print("Twist:", sec.twist(flow))
print("TRM:", sec.trm_reduce(flow))
print("Anomaly score (znormalizowany):", sec.anomaly_score(flow))

print("\n=== TIMDR Server (serwer produkcyjny) ===")
srv = TIMDRServer()
metrics = [
    [20, 40, 0.5, 0],
    [22, 41, 0.6, 10],
    [95, 42, 4.0, 20],   # nagly skok CPU/load
    [30, 43, 0.7, 30],
    [25, 44, 0.6, 40],
]
print("Twist (nagle anomalie):", srv.twist(metrics))

# przyklad licznika monotonicznego (np. node_exporter bytes_total) z restartem
counters = [10_000_000, 10_050_000, 500, 20_000]  # restart miedzy pkt 1 a 2
t = [0, 10, 20, 30]
print("Surowy licznik ->", counters)
print("Rate bez obslugi resetu:", srv.counters_to_rates(counters, t, handle_resets=False))
print("Rate z obsluga resetu:  ", srv.counters_to_rates(counters, t, handle_resets=True))
