import numpy as np
import pytest
from timdr_server import TIMDRServer


@pytest.fixture
def srv():
    return TIMDRServer()


def test_walidacja_ksztaltu(srv):
    with pytest.raises(ValueError):
        srv.twist([[50, 60], [51, 61]])


def test_walidacja_nierosnacy_czas(srv):
    with pytest.raises(ValueError):
        srv.twist([[50, 60, 1.0, 0], [51, 61, 1.1, 0]])


def test_nagly_skok_cpu_wykryty(srv):
    metrics = [[20, 40, 0.5, i] for i in range(5)]
    metrics[3] = [95, 40, 0.5, 3]  # nagly skok CPU
    result = srv.twist(metrics)
    assert len(result["cpu_twist"]) > 0


def test_trend_wykrywa_powolny_wyciek_pamieci_ktorego_twist_pomija(srv):
    """
    Kluczowy test: syntetyczny wyciek pamięci +0.4pp/próbkę przez 30 próbek
    (co 10s). Kazdy pojedynczy krok jest za maly zeby twist() go zlapal,
    ale trend() powinien wykryc stale rosnace nachylenie.
    """
    n = 30
    mem = [40.0 + 0.4 * i for i in range(n)]
    t = [i * 10.0 for i in range(n)]
    metrics = [[20.0, mem[i], 0.5, t[i]] for i in range(n)]

    twist_result = srv.twist(metrics)
    assert len(twist_result["mem_twist"]) == 0, (
        "twist() wykrył coś w łagodnym, liniowym wycieku - test zbudowany źle"
    )

    trend_result = srv.trend(metrics, window=6, slope_thresh_per_min=1.0, column=1)
    assert len(trend_result) > 0, "trend() nie wykrył wycieku pamięci"
    assert all(f["slope_per_min"] > 0 for f in trend_result)


def test_trend_brak_alarmu_dla_stabilnej_metryki(srv):
    n = 20
    metrics = [[20.0, 40.0 + np.sin(i) * 0.1, 0.5, i * 10.0] for i in range(n)]
    trend_result = srv.trend(metrics, window=6, slope_thresh_per_min=1.0, column=1)
    assert len(trend_result) == 0


def test_counters_to_rates_podstawowe(srv):
    counters = [1000, 1500, 2200, 3000]
    t = [0, 10, 20, 30]
    rates = srv.counters_to_rates(counters, t)
    assert len(rates) == len(counters)
    assert np.allclose(rates[1:], [50.0, 70.0, 80.0])
    assert not np.any(np.isnan(rates))


def test_counters_to_rates_obsluga_restartu(srv):
    """
    Restart procesu -> licznik spada z 5000 do 0. Bez obsługi resetu
    dałoby to ogromną ujemną 'prędkość'. Z obsługą - 0 przyrostu w tym
    kroku, nie fałszywy spadek.
    """
    counters = [4000, 5000, 100, 600]  # reset miedzy indeksem 1 a 2
    t = [0, 10, 20, 30]
    rates = srv.counters_to_rates(counters, t, handle_resets=True)
    assert rates[2] == 0.0, f"reset nie obsłużony poprawnie: {rates}"
    assert np.all(rates >= 0)

    rates_no_fix = srv.counters_to_rates(counters, t, handle_resets=False)
    assert rates_no_fix[2] < 0  # bez poprawki widac falszywy ujemny skok


def test_trm_reduce_zachowuje_konce(srv):
    metrics = [[20, 40, 0.5, i] for i in range(5)]
    smooth = srv.trm_reduce(metrics)
    assert np.allclose(smooth[0], [20, 40, 0.5])
    assert np.allclose(smooth[-1], [20, 40, 0.5])
