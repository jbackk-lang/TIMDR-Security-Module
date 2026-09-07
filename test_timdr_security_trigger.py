"""
test_timdr_security_trigger.py — testy naprawy timdr_security_trigger.py.

Kontekst (patrz naglowek pliku): dostarczona wersja triggera nigdy nie
dzialala na prawdziwym API TIMDRSecurity/TIMDRServer - zakladala, ze
twist() zwraca liste per-probke i anomaly_score() liste slownikow z
kluczem "z_norm", podczas gdy w rzeczywistosci twist() zwraca JEDEN
slownik tablic indeksow, a anomaly_score() plaska tablice liczb; do tego
STRUCTURE sprawdzal nieistniejacy klucz "bytes_twist", CONTINUITY mial
samo-zatruwajacy sie prog (delta > max(dt)*3 nigdy nie moze byc prawda dla
NAJWIEKSZEJ przerwy porownanej z sama soba), a scale_thresh/
trend_slope_thresh_per_min byly martwymi parametrami konstruktora (nigdy
nie przekazywane do twist()/trend()).

Wszystkie oczekiwane wartosci ponizej wyprowadzone RECZNIE (LOO z-score,
gradient centralny/jednostronny) z tych samych, juz zweryfikowanych w
repo przykladow (test_timdr_security.py::test_ddos_wykryty_ratio_i_connections,
demo.py, test_timdr_server.py::test_trend_wykrywa_powolny_wyciek_pamieci...),
nie zgadywane - patrz obliczenia w opisie kazdego testu.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from timdr_security_trigger import TIMDRSecurityTrigger, SecurityTriggerType


# Ten sam DDoS flow co test_timdr_security.py::test_ddos_wykryty_ratio_i_connections
DDOS_FLOW = [
    [1000, 800, 12, 0],
    [1200, 900, 13, 1],
    [1500, 1100, 14, 2],
    [5000, 2000, 40, 3],
    [5200, 2100, 42, 4],
]

# Ten sam metrics co demo.py ("nagly skok CPU/load")
SPIKE_METRICS = [
    [20, 40, 0.5, 0],
    [22, 41, 0.6, 10],
    [95, 42, 4.0, 20],
    [30, 43, 0.7, 30],
    [25, 44, 0.6, 40],
]

# Ten sam wyciek pamieci co test_timdr_server.py::test_trend_wykrywa_powolny...
MEMLEAK_METRICS = [[20.0, 40.0 + 0.4 * i, 0.5, i * 10.0] for i in range(30)]


def test_flow_ddos_wykrywa_structure_nie_scale():
    """
    Reczny rachunek: dratio przy idx2/idx3 = 0.583/0.556 (oba >0.4 ->
    ratio_idx={2,3}). dconns przy idx2/idx3 = 13.5/14.0, LOO z-score
    ~16.2/16.9 (oba >3.5 -> conn_idx={2,3}). ratio_idx i conn_idx maja
    WSPOLNE indeksy {2,3} -> STRUCTURE (kilka sygnalow naraz) ma
    pierwszenstwo przed SCALE, lokalizacja = min({2,3}) = 2.
    """
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_flow(DDOS_FLOW)
    assert result.triggered is True
    assert result.trigger_type == SecurityTriggerType.STRUCTURE
    assert result.location == 2


def test_flow_stabilny_ruch_brak_triggera():
    """Ten sam plaski ruch co test_brak_anomalii_stabilny_ruch - zero
    twistow, zero anomalii, rowne odstepy czasu -> NONE."""
    flow = [[1000, 800, 12, i] for i in range(6)]
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_flow(flow)
    assert result.triggered is False
    assert result.trigger_type == SecurityTriggerType.NONE


def test_flow_wykrywa_dziure_w_probkowaniu():
    """
    Metryki stale (zero twist/anomaly), ale odstepy czasu = [1,1,8,1] ->
    przerwa o wartosci 8 wobec pozostalych [1,1,1] (leave-one-out, NIE wobec
    samej siebie - patrz POPRAWKA #2) przekracza factor=3 -> CONTINUITY na
    idx 3 (delta miedzy probka 2 a 3, index+1=3).
    """
    flow = [
        [1000, 800, 12, 0],
        [1000, 800, 12, 1],
        [1000, 800, 12, 2],
        [1000, 800, 12, 10],
        [1000, 800, 12, 11],
    ]
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_flow(flow)
    assert result.triggered is True
    assert result.trigger_type == SecurityTriggerType.CONTINUITY
    assert result.location == 3


def test_server_spike_wykrywa_scale_nie_structure():
    """
    Reczny rachunek (gradient jednostronny/centralny na 5 punktach, LOO
    z-score): cpu_idx={1,3} (z~5.85/5.70), load_idx={1,3} (z~11.97/11.97),
    mem_idx={} (mem rosnie idealnie liniowo -> gradient stały -> z=0
    wszedzie). cpu ∩ mem = pusty -> nie STRUCTURE. Polaczone {1,3} ->
    SCALE, lokalizacja = min({1,3}) = 1 (NIE 2, mimo ze sama wartosc cpu=95
    jest w wierszu 2 - gradient centralny wykrywa skok w sasiednich
    indeksach, tak jak w DDOS_FLOW powyzej).
    """
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_server(SPIKE_METRICS)
    assert result.triggered is True
    assert result.trigger_type == SecurityTriggerType.SCALE
    assert result.location == 1


def test_server_wyciek_pamieci_wykrywa_model_conflict():
    """
    Ten sam wyciek co test_trend_wykrywa_powolny_wyciek_pamieci... - twist()
    nie widzi go (gradient stale ~0.04/s, LOO z=0), trend() (domyslny
    prog 1.0pp/min, teraz FAKTYCZNIE przekazywany - POPRAWKA #3) widzi
    stale nachylenie 2.4pp/min > 1.0. Kazde z 25 okien (window=6) ma
    identyczne nachylenie (idealna prosta) -> max() bierze PIERWSZE
    (start=0,end_idx=5).
    """
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_server(MEMLEAK_METRICS)
    assert result.triggered is True
    assert result.trigger_type == SecurityTriggerType.MODEL_CONFLICT
    assert result.location == 5


def test_server_trend_slope_thresh_faktycznie_wplywa_na_wynik():
    """
    REGRESJA POPRAWKI #3: przed naprawa trend_slope_thresh_per_min nigdy
    nie trafial do srv.trend() (zawsze uzywany byl HARDKODOWANY domyslny
    prog 1.0), wiec ten test bylby ZAWSZE identyczny jak poprzedni,
    niezaleznie od podanej wartosci. Wyciek ma nachylenie 2.4pp/min - przy
    progu 5.0 (> 2.4) trend() poprawnie nie zglasza nic, a bez zadnego
    innego sygnalu w tych danych wynik to NONE.
    """
    trigger = TIMDRSecurityTrigger(trend_slope_thresh_per_min=5.0)
    result = trigger.analyze_server(MEMLEAK_METRICS)
    assert result.triggered is False
    assert result.trigger_type == SecurityTriggerType.NONE


def test_server_scale_thresh_faktycznie_wplywa_na_wynik():
    """
    REGRESJA POPRAWKI #3 (druga polowa): przed naprawa scale_thresh nigdy
    nie trafial do srv.twist() (zawsze hardkodowany prog 3.5), wiec
    podniesienie go nie mialo ZADNEGO efektu. Przy scale_thresh=100 zadien
    z policzonych LOO z-score (max ~11.97) go nie przekracza -> SCALE
    znika, ale metryka pamieci w tych samych danych (demo.py) rosnie
    liniowo +1pp/10s = 6pp/min, powyzej domyslnego trend_slope_thresh (1.0)
    -> ujawnia sie MODEL_CONFLICT z trend(), ktory bez poprawki nigdy nie
    byl osiagalny (SCALE zawsze wygrywal pierwszy).
    """
    trigger = TIMDRSecurityTrigger(scale_thresh=100.0)
    result = trigger.analyze_server(SPIKE_METRICS)
    assert result.triggered is True
    assert result.trigger_type == SecurityTriggerType.MODEL_CONFLICT
    assert result.location == 4


def test_get_last_zwraca_ostatni_wynik():
    trigger = TIMDRSecurityTrigger()
    result = trigger.analyze_flow(DDOS_FLOW)
    assert trigger.get_last() is result
