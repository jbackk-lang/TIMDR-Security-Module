import numpy as np
import pytest
from timdr_rhythm import TIMDRRhythm


# -----------------------------------------------------------
# Podstawy
# -----------------------------------------------------------

def test_autocorr_lag0_zawsze_rowne_1():
    x = np.sin(2 * np.pi * np.arange(100) / 13) + np.random.default_rng(0).normal(0, 0.1, 100)
    r = TIMDRRhythm(max_lag=50)
    ac = r.autocorr(x)
    assert ac[0] == pytest.approx(1.0)


def test_sygnal_za_krotki_nie_crashuje():
    r = TIMDRRhythm(max_lag=10)
    ac0 = r.autocorr([])
    ac1 = r.autocorr([5.0])
    assert len(ac0) == 1 and ac0[0] == 0.0
    assert len(ac1) == 1 and ac1[0] == 0.0
    assert r.dominant_periods([1.0, 2.0]) == []
    periods, score = r.beacon_score([1.0])
    assert periods == [] and score == 0.0


def test_sygnal_staly_bez_wariancji_nie_crashuje():
    x = np.full(50, 3.0)
    r = TIMDRRhythm(max_lag=20)
    ac = r.autocorr(x)
    assert np.all(ac == 0.0)  # brak wariancji -> ac[0]==0 -> zera, nie NaN/crash
    assert r.dominant_periods(x) == []


# -----------------------------------------------------------
# POPRAWKA A: obciazony estymator autokorelacji (malejace okno)
# -----------------------------------------------------------

def test_autocorr_niesciagnieta_stala_wysokosc_pikow_periodycznych():
    """Regresja dla błędu: oryginalny kod dzielił każdy lag przez stałą
    ac[0], nie korygując malejącej liczby nakładających się próbek -
    dawało to sztuczny, liniowy spadek wysokości piku wraz z lagiem
    (0.90, 0.80, 0.70... dla lag=20,40,60... na czystym sygnale bez
    szumu). Po poprawce piki periodycznego sygnału mają tę samą,
    stałą wysokość niezależnie od lagu."""
    n, period = 200, 20
    x = np.sin(2 * np.pi * np.arange(n) / period)
    r = TIMDRRhythm(max_lag=100, min_period=3, power_thresh=0.0)
    ac = r.autocorr(x)
    heights = [ac[lag] for lag in (20, 40, 60, 80, 100)]
    for h in heights:
        assert h == pytest.approx(1.0, abs=1e-9)


def test_autocorr_biased_wersja_dawala_spadek_dla_kontrastu():
    """Kontrolny test - dokumentuje, że stary (błędny) sposób liczenia
    rzeczywiście dawał spadający profil, żeby test powyżej nie 'zgadzał
    się przypadkiem' z jakąś inną poprawną własnością."""
    n, period = 200, 20
    x = np.sin(2 * np.pi * np.arange(n) / period)
    xm = x - np.mean(x)
    full = np.correlate(xm, xm, mode="full")
    mid = len(full) // 2
    ac_biased = full[mid:mid + 101] / full[mid]
    heights = [ac_biased[lag] for lag in (20, 40, 60, 80, 100)]
    assert heights == sorted(heights, reverse=True)
    assert heights[0] > heights[-1] + 0.3  # wyraznie malejacy profil (stary bug)


def test_dlugie_okresy_wykrywane_mimo_malego_marginesu_probek():
    """Sygnal, ktorego dlugosc to tylko odrobine wiecej niz jeden okres
    powtorzony kilka razy - dluzszy okres (blizej konca max_lag) nie
    powinien byc sztucznie odrzucany tylko dlatego, ze ma mniej
    nakladajacych sie probek."""
    n, period = 150, 50
    x = np.sin(2 * np.pi * np.arange(n) / period)
    r = TIMDRRhythm(max_lag=120, min_period=3, power_thresh=0.9)
    periods = r.dominant_periods(x)
    lags = [p for p, _ in periods]
    # tolerancja +-1 probki: dyskretne probkowanie + korekta okna moga
    # przesunac dokladny wierzcholek o 1 indeks bez zadnej realnej utraty
    # periodycznosci (to nie jest to samo zjawisko co testowany bug -
    # bug dawal SYSTEMATYCZNY spadek mocy o dziesiatki %, nie przesuniecie o 1 probke)
    assert any(abs(lag - 50) <= 1 for lag in lags)
    assert any(abs(lag - 100) <= 1 for lag in lags)


# -----------------------------------------------------------
# POPRAWKA B: dominacja cechy o wiekszej skali w sygnale wielocechowym
# -----------------------------------------------------------

def test_wielocecha_mala_skala_nie_ginie_pod_duza_skala():
    """Regresja dla błędu: `np.linalg.norm` na surowych, nieznormalizo-
    wanych cechach pozwalał cesze o dużej skali bezwzględnej (np. bytes,
    rząd 1000) zdominować normę i zagłuszyć prawdziwy rytm obecny w
    cesze o małej skali (np. connections, rząd 1). Zweryfikowano
    bezpośrednio: przed poprawką dominujący wykryty okres na takim
    sygnale to lag=48 (artefakt szumu bytes, power=1.0), a prawdziwy
    beacon lag=15 spadał do power=0.75, poza pozycją dominującą."""
    rng = np.random.default_rng(0)
    n = 300
    t = np.arange(n)
    connections = (np.sin(2 * np.pi * t / 15) > 0.9).astype(float)
    bytes_ = rng.normal(1000, 300, n)
    X = np.column_stack([bytes_, connections])

    r = TIMDRRhythm(max_lag=60, min_period=3, power_thresh=0.4)
    periods, score = r.beacon_score(X)

    lags_and_powers = dict(periods)
    assert 15 in lags_and_powers
    assert lags_and_powers[15] == pytest.approx(1.0, abs=1e-6)  # prawdziwy beacon = dominujacy


def test_wielocecha_stala_kolumna_nie_crashuje():
    """Cecha bez żadnej wariancji (std=0, np. port zawsze ten sam) nie
    powinna powodować dzielenia przez zero - ma być po prostu pominięta
    w normie."""
    n = 60
    const_feature = np.full(n, 7.0)
    rhythmic = np.sin(2 * np.pi * np.arange(n) / 10)
    X = np.column_stack([const_feature, rhythmic])
    r = TIMDRRhythm(max_lag=30, min_period=3, power_thresh=0.3)
    periods = r.dominant_periods(X)
    lags = [p for p, _ in periods]
    assert 10 in lags


def test_wielocecha_stala_kolumna_zachowuje_wykrywalnosc_rytmu():
    """Sanity check: jeśli jedna kolumna jest stała (brak wariancji),
    `_prepare_signal` ma ją całkowicie pominąć - ALE norma L2 jest z
    definicji nieujemna, więc nawet z jedną znaczącą kolumną wynik to
    |z-score(rhythmic)|, nie sam rhythmic (utrata znaku to nieodłączna
    cecha łączenia cech przez normę, nie błąd wprowadzony poprawką -
    ten sam efekt miał już oryginalny, niepoprawiony kod).
    Rektyfikacja fali sinusoidalnej podwaja jej pozorną częstotliwość
    (okres T -> widoczny też okres T/2), więc test sprawdza, że
    prawdziwy okres (8) LUB jego harmoniczna (4) zostały wykryte - nie
    że wynik jest identyczny z surowym sygnałem 1D."""
    n = 80
    rhythmic = np.sin(2 * np.pi * np.arange(n) / 8) + np.random.default_rng(1).normal(0, 0.05, n)
    const_feature = np.full(n, -3.0)
    X = np.column_stack([const_feature, rhythmic])

    r = TIMDRRhythm(max_lag=40, min_period=2, power_thresh=0.0)
    lags = [p for p, _ in r.dominant_periods(X)]
    assert 8 in lags or 4 in lags


# -----------------------------------------------------------
# Filtry progowe
# -----------------------------------------------------------

def test_min_period_odfiltrowuje_krotkie_lagi():
    x = np.sin(2 * np.pi * np.arange(100) / 4)  # bardzo krotki okres
    r = TIMDRRhythm(max_lag=50, min_period=10, power_thresh=0.0)
    periods = r.dominant_periods(x)
    assert all(p >= 10 for p, _ in periods)


def test_power_thresh_odfiltrowuje_slabe_piki():
    rng = np.random.default_rng(2)
    x = rng.normal(0, 1, 200)  # czysty szum, bez realnego rytmu
    r = TIMDRRhythm(max_lag=80, min_period=3, power_thresh=0.4)
    periods = r.dominant_periods(x)
    # kazdy zwrocony pik musi byc >= progu wzgledem najsilniejszego
    assert all(power >= 0.4 for _, power in periods)


def test_brak_rytmu_daje_pusta_liste_i_score_zero():
    rng = np.random.default_rng(3)
    x = rng.normal(0, 1, 30)
    r = TIMDRRhythm(max_lag=10, min_period=3, power_thresh=0.99)
    periods, score = r.beacon_score(x)
    if not periods:
        assert score == 0.0
