"""
Test walidacyjny wg protokołu §13 skilla `timdr-signal-framework`:
syntetyczny szum tła + atak wstrzyknięty w losowym miejscu, W WIELU
niezależnych próbach, Z jawną kontrolą negatywną (próby bez ataku),
dający prawdziwy wskaźnik wykrycia i fałszywych alarmów — nie tylko
"testy przechodzą" na jednym ręcznie dobranym przykładzie.

PRE-REJESTRACJA (patrz też `docs_synthetic_validation_result.md` w tym
repo dla pełnego opisu i wyników jednego przebiegu na 300+300 próbach):

- Tło: N=60 kroków, bytes_in ~ N(3000,300), bytes_out skorelowany
  (0.8*bytes_in + szum), connections ~ Poisson(15)+5.
- Atak: start w losowym t_a w [15,45), czas trwania losowy w {3,4,5},
  mnożnik amplitudy losowy w [3x,10x] dla bytes_in/connections,
  asymetryczny mnożnik dla bytes_out (typowe dla DDoS: in >> out).
- Kontrola negatywna: identyczny generator tła, BEZ wstrzyknięcia.
- Wykrycie: jakikolwiek indeks w `ratio_twist`/`connection_twist` w
  oknie [t_a-1, koniec_ataku+1].
- Fałszywy alarm: jakikolwiek indeks POZA tym oknem (próby z atakiem)
  lub jakikolwiek indeks w ogóle (próby bez ataku).

Ten plik używa mniejszej liczby prób (100+100) niż oryginalny
przebieg walidacyjny (300+300) żeby test uruchamiał się szybko w CI;
liczby graniczne w assercjach mają margines względem zaobserwowanego
w pełnym przebiegu wyniku (patrz komentarze przy każdej asercji).
"""
import numpy as np
import pytest
from timdr_security import TIMDRSecurity

N = 60
N_TRIALS = 100


def _make_background(rng):
    bytes_in = rng.normal(3000, 300, N)
    bytes_out = bytes_in * 0.8 + rng.normal(0, 150, N)
    connections = rng.poisson(15, N) + 5
    t = np.arange(N, dtype=float)
    bytes_in = np.clip(bytes_in, 100, None)
    bytes_out = np.clip(bytes_out, 100, None)
    return bytes_in, bytes_out, connections.astype(float), t


def _inject_attack(bytes_in, bytes_out, connections, rng):
    t_a = rng.integers(15, 45)
    dur = rng.integers(3, 6)
    mult = rng.uniform(3.0, 10.0)
    bi, bo, cc = bytes_in.copy(), bytes_out.copy(), connections.copy()
    end = min(t_a + dur, N)
    bi[t_a:end] *= mult
    bo[t_a:end] *= (mult * rng.uniform(0.3, 0.6))
    cc[t_a:end] *= mult
    return bi, bo, cc, t_a, end


@pytest.fixture
def sec():
    return TIMDRSecurity()


def test_synthetic_ddos_detection_rate_wysoki(sec):
    """
    Kontrola pozytywna: atak wstrzyknięty w losowym miejscu w N_TRIALS
    niezależnych próbach z realistycznym szumem tła (nie jeden ręcznie
    dobrany przykład). W pełnym przebiegu walidacyjnym (300 prób,
    seed=42) wynik był 300/300 = 100%. Wymagamy tu >= 0.95 z
    marginesem na inny seed/mniejszą próbę.
    """
    rng = np.random.default_rng(123)
    n_detected = 0
    for _ in range(N_TRIALS):
        bi, bo, cc, t = _make_background(rng)
        bi, bo, cc, t_a, end = _inject_attack(bi, bo, cc, rng)
        flow = np.column_stack([bi, bo, cc, t])
        result = sec.twist(flow)
        flagged = set(result["ratio_twist"]) | set(result["connection_twist"])
        win = set(range(max(0, t_a - 1), min(N, end + 1)))
        if flagged & win:
            n_detected += 1
    rate = n_detected / N_TRIALS
    assert rate >= 0.95, f"wskaznik wykrycia {rate:.2%} ponizej oczekiwanego (bazowo: 100% na 300 probach)"


def test_synthetic_negative_control_false_alarm_rate_udokumentowany(sec):
    """
    Kontrola negatywna: CZYSTE tło, bez żadnego ataku. Pełny przebieg
    walidacyjny (300 prób) dał 23.0% fałszywych alarmów — WYŁĄCZNIE z
    `connection_twist` (0% z `ratio_twist`), czyli robust
    leave-one-out z-score przy progu domyślnym 3.5 jest wrażliwszy niż
    naiwna intuicja "z-score>3.5 to <0.1% szans" sugerowałaby, bo szum
    Poissona + gradient względem czasu nie jest dokładnie i.i.d.
    normalny, do czego z-score milcząco się odwołuje.

    To NIE jest regresja do naprawienia — to udokumentowane
    ograniczenie domyślnego progu, zgodnie z zastrzeżeniem w README
    ("progi domyślne to punkt startowy, nie zwalidowana wartość").
    Test pilnuje, żeby fałszywy odsetek nie wzrósł jeszcze bardziej
    (np. przez przyszłą zmianę w `_robust_loo_zscore`) bez świadomej
    decyzji.
    """
    rng = np.random.default_rng(123)
    n_false_alarm = 0
    n_false_alarm_ratio = 0
    n_false_alarm_conns = 0
    for _ in range(N_TRIALS):
        bi, bo, cc, t = _make_background(rng)
        flow = np.column_stack([bi, bo, cc, t])
        result = sec.twist(flow)
        if len(result["ratio_twist"]) > 0:
            n_false_alarm_ratio += 1
        if len(result["connection_twist"]) > 0:
            n_false_alarm_conns += 1
        if len(result["ratio_twist"]) > 0 or len(result["connection_twist"]) > 0:
            n_false_alarm += 1
    rate = n_false_alarm / N_TRIALS
    # Bazowo 23.0% na 300 probach (seed=42). Margines szeroki (do 40%)
    # bo to dokumentacja znanego zachowania, nie scislo wycechowany limit.
    assert rate <= 0.40, (
        f"wskaznik falszywych alarmow na czystym tle {rate:.2%} istotnie "
        f"wyzszy niz udokumentowana baza (~23%) - sprawdz czy prog domyslny "
        f"lub _robust_loo_zscore sie nie zmienily"
    )
    assert n_false_alarm_ratio == 0, (
        "ratio_twist zaczal generowac falszywe alarmy na czystym tle "
        "(bazowo 0% w pelnym przebiegu) - sprawdz ratio_thresh"
    )


def test_synthetic_anomaly_score_separuje_atak_od_tla(sec):
    """
    Test Manna-Whitneya (SS13 punkt 3, "prawdziwy test istotnosci"):
    anomaly_score() w oknie ataku powinien byc statystycznie wiekszy
    niz w czystym tle. W pelnym przebiegu (300+300 prob): mediana w
    oknie ataku 14.6 vs mediana w tle 1.4, p < 1e-300 (efektywnie 0).
    """
    from scipy import stats

    rng = np.random.default_rng(123)
    attack_scores = []
    background_scores = []
    for _ in range(N_TRIALS):
        bi, bo, cc, t = _make_background(rng)
        bi, bo, cc, t_a, end = _inject_attack(bi, bo, cc, rng)
        flow = np.column_stack([bi, bo, cc, t])
        score = sec.anomaly_score(flow, normalize=True)
        attack_scores.extend(score[t_a:end])

    for _ in range(N_TRIALS):
        bi, bo, cc, t = _make_background(rng)
        flow = np.column_stack([bi, bo, cc, t])
        score = sec.anomaly_score(flow, normalize=True)
        background_scores.extend(score)

    u, p = stats.mannwhitneyu(attack_scores, background_scores, alternative="greater")
    assert p < 0.001, f"anomaly_score nie separuje ataku od tla istotnie statystycznie (p={p:.4g})"
    assert np.median(attack_scores) > np.median(background_scores)
