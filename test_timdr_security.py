import numpy as np
import pytest
from timdr_security import TIMDRSecurity


@pytest.fixture
def sec():
    return TIMDRSecurity()


def test_walidacja_ksztaltu(sec):
    with pytest.raises(ValueError):
        sec.twist([[1000, 800, 12], [1200, 900, 13]])


def test_walidacja_nierosnacy_czas(sec):
    with pytest.raises(ValueError):
        sec.twist([[1000, 800, 12, 0], [1200, 900, 13, 0]])


def test_ddos_wykryty_ratio_i_connections(sec):
    """
    Przykład DDoS ze zgłoszenia. W ORYGINALNYM kodzie connection_twist
    wychodził pusty (bug samo-zatruwającego się progu) mimo że to
    flagowy przykład z README. Po poprawce oba typy twistu powinny
    wykryć anomalię w okolicach punktu 3.
    """
    flow = [
        [1000, 800, 12, 0],
        [1200, 900, 13, 1],
        [1500, 1100, 14, 2],
        [5000, 2000, 40, 3],
        [5200, 2100, 42, 4],
    ]
    result = sec.twist(flow)
    assert len(result["ratio_twist"]) > 0
    assert len(result["connection_twist"]) > 0, (
        "connection_twist pusty - regresja bugu samo-zatruwającego się progu"
    )
    assert 2 in result["connection_twist"] or 3 in result["connection_twist"]


def test_prog_connections_niezalezny_od_probkowania(sec):
    flow_fast = [[1000,800,10,0],[1000,800,10,1],[1000,800,10,2],[1000,800,60,3],[1000,800,60,4]]
    flow_slow = [[1000,800,10,0],[1000,800,10,4],[1000,800,10,8],[1000,800,60,12],[1000,800,60,16]]
    r_fast = sec.twist(flow_fast)["connection_twist"]
    r_slow = sec.twist(flow_slow)["connection_twist"]
    # oba powinny wykryc anomalie (ta sama sekwencja wartosci), niezaleznie od dt
    assert len(r_fast) > 0
    assert len(r_slow) > 0


def test_anomaly_score_nie_jest_slepy_na_connections(sec):
    """
    Regresja bugu braku normalizacji jednostek: realna anomalia
    connections (10 -> 80, lateral movement) powinna dać WYŻSZY
    znormalizowany anomaly_score niż zwykły szum bajtów w punkcie bez
    żadnej anomalii.
    """
    flow = [
        [50000, 48000, 10, 0],
        [51000, 48500, 11, 1],
        [49500, 47800, 9,  2],
        [50200, 48100, 80, 3],
        [50100, 48050, 82, 4],
    ]
    score = sec.anomaly_score(flow, normalize=True)
    # punkt 3 (realna anomalia connections) powinien miec wyzszy score
    # niz punkt 0 (sam szum bajtow, brak anomalii)
    assert score[3] > score[0], (
        f"score[3]={score[3]:.2f} nie jest wiekszy niz score[0]={score[0]:.2f} "
        f"- anomalia connections nadal przykryta szumem bajtow"
    )


def test_trm_reduce_zachowuje_konce(sec):
    flow = [[1000,800,12,0],[1200,900,13,1],[1500,1100,14,2],[5000,2000,40,3],[5200,2100,42,4]]
    smooth = sec.trm_reduce(flow)
    assert np.allclose(smooth[0], [1000,800,12])
    assert np.allclose(smooth[-1], [5200,2100,42])
    assert not np.any(np.isnan(smooth))


def test_brak_anomalii_stabilny_ruch(sec):
    flow = [[1000,800,12,i] for i in range(6)]
    result = sec.twist(flow)
    assert len(result["ratio_twist"]) == 0
    assert len(result["connection_twist"]) == 0
