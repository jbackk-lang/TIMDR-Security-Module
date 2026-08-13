"""
TIMDR Security Module — timdr_security.py
==========================================
Analiza przepływu sieciowego: gradient zmian (TIMDR-flow), detekcja
"twistów" (nagłych zmian proporcji ruchu / liczby połączeń), redukcja
szumu (TRM) i scoring anomalii.

Wejście: lista punktów [bytes_in, bytes_out, connections, t]
"""

import numpy as np


class TIMDRSecurity:
    def __init__(self):
        pass

    # ------------------------------------------------------------
    @staticmethod
    def _validate(flow, min_points=2):
        f = np.asarray(flow, dtype=np.float64)
        if f.ndim != 2 or f.shape[1] != 4:
            raise ValueError(
                f"flow musi mieć kształt (N, 4) [bytes_in, bytes_out, connections, t], "
                f"dostano {f.shape}"
            )
        if len(f) < min_points:
            raise ValueError(f"flow musi mieć co najmniej {min_points} punkty, dostano {len(f)}")
        t = f[:, 3]
        if np.any(np.diff(t) <= 0):
            raise ValueError("znaczniki czasu (kolumna t) muszą być ściśle rosnące (dt > 0)")
        return f

    @staticmethod
    def _robust_loo_zscore(x):
        """
        Robust "leave-one-out" z-score: dla każdego punktu i licz medianę i MAD
        z WSZYSTKICH POZOSTAŁYCH punktów (bez i), potem z-score punktu i
        względem tej bazowej statystyki.

        POPRAWKA (bug samo-zatruwającego się progu adaptacyjnego): oryginalny
        kod liczył `np.mean(np.abs(dconns)) * 3` na CAŁEJ próbce WŁĄCZNIE z
        samym badanym punktem. Gdy w próbce jest realna anomalia, ona sama
        zawyża próg, który ma ją wykryć. Zweryfikowano na przykładzie DDoS
        ze zgłoszenia: dconns w punkcie anomalii = 13.5-14.0, próg
        mean*3 = 18.9 (zawyżony PRZEZ tę anomalię) -> `connection_twist`
        wychodził PUSTY, mimo że README opisuje to jako flagowy przykład
        wykrywanego ataku. Po poprawce (baseline liczona bez badanego
        punktu, mediana+MAD zamiast średniej+odch. std.) ten sam punkt
        dostaje z-score ~16-17 (jednoznaczna anomalia), a normalne punkty
        z-score <1.
        """
        x = np.asarray(x, dtype=np.float64)
        n = len(x)
        z = np.zeros(n)
        for i in range(n):
            others = np.delete(x, i)
            med = np.median(others)
            mad = np.median(np.abs(others - med))
            mad = mad if mad > 1e-9 else 1e-9
            z[i] = abs(x[i] - med) / (1.4826 * mad)  # 1.4826: MAD -> odpowiednik odch. std. dla rozkladu normalnego
        return z

    # --- 1. TIMDR-flow: gradient zmian w ruchu sieciowym ---
    def timdr_flow(self, flow):
        """
        flow: lista punktów [bytes_in, bytes_out, connections, t]
        zwraca: TIMDR-flow (gradient prędkości+przyspieszenia zmian)
        """
        f = self._validate(flow)
        metrics = f[:, :3]
        t = f[:, 3]

        v = np.gradient(metrics, t, axis=0)
        a = np.gradient(v, t, axis=0)

        # POPRAWKA: tak jak w TIMDR-Radar-Module / FLIGHT-TRACKING-TIMDR -
        # ostatni gradient też liczony względem rzeczywistego czasu t.
        flow_grad = np.gradient(v + a, t, axis=0)
        return flow_grad

    # --- 2. Twist: nagłe zmiany kierunku ruchu ---
    def twist(self, flow, ratio_thresh=0.4, conns_z_thresh=3.5):
        """
        wykrywa twist:
        - nagłe zmiany proporcji ruchu (in/out), próg w jednostkach/s
        - anomalie w liczbie połączeń (robust z-score, próg domyślny 3.5)
        """
        f = self._validate(flow)
        bytes_in = f[:, 0]
        bytes_out = f[:, 1]
        conns = f[:, 2]
        t = f[:, 3]

        ratio = bytes_in / (bytes_out + 1e-6)
        # POPRAWKA: gradient liczony względem czasu, nie indeksu próbki -
        # inaczej ten sam wzorzec wartości próbkowany z inną częstotliwością
        # dawał identyczny wynik niezależnie od realnej dynamiki w czasie
        # (zweryfikowano: próbkowanie co 1s i co 4s dla tej samej sekwencji
        # wartości dawało IDENTYCZNE twist_ratio, mimo 4x różnej rzeczywistej
        # szybkości zmian).
        dratio = np.gradient(ratio, t)
        dconns = np.gradient(conns, t)

        twist_ratio = np.where(np.abs(dratio) > ratio_thresh)[0]

        # POPRAWKA: robust leave-one-out z-score zamiast mean(|dconns|)*3
        # liczonego na całej próbce włącznie z badanym punktem (patrz
        # docstring _robust_loo_zscore).
        z = self._robust_loo_zscore(dconns)
        twist_conns = np.where(z > conns_z_thresh)[0]

        return {"ratio_twist": twist_ratio, "connection_twist": twist_conns}

    # --- 3. TRM-reduction: stabilizacja sygnału ---
    def trm_reduce(self, flow):
        """
        TRM: prosta redukcja szumu (średnia krocząca 3-punktowa).
        Pierwszy i ostatni punkt pozostają bez zmian.
        """
        f = self._validate(flow)
        metrics = f[:, :3]
        smooth = metrics.copy()
        for i in range(1, len(metrics) - 1):
            smooth[i] = (metrics[i - 1] + metrics[i] + metrics[i + 1]) / 3.0
        return smooth

    # --- 4. Anomaly score ---
    def anomaly_score(self, flow, normalize=True):
        """
        Scoring anomalii na podstawie normy gradientu TIMDR-flow.

        POPRAWKA (bug braku normalizacji jednostek): oryginalny kod liczył
        `np.linalg.norm(grad, axis=1)` wprost na [bytes_in, bytes_out,
        connections] bez żadnej normalizacji. Bajty (rzędu dziesiątek
        tysięcy) numerycznie dominują nad connections (rzędu dziesiątek) w
        normie L2. Zweryfikowano na przykładzie: zwykły szum bajtów w
        punkcie bez żadnej anomalii dawał WYŻSZY anomaly_score (782.8, w
        97.9% pochodzący z bajtów) niż punkt z realnym 8-krotnym wzrostem
        liczby połączeń (204.2, tylko 20.9% z connections) - dokładnie
        odwrotnie niż powinno być. Poprawka: każda cecha jest normalizowana
        (odejmowana mediana, dzielona przez MAD) PRZED połączeniem w normę,
        więc żadna cecha nie dominuje wyłącznie z powodu jednostek.
        """
        grad = self.timdr_flow(flow)
        if normalize:
            med = np.median(grad, axis=0)
            mad = np.median(np.abs(grad - med), axis=0)
            mad = np.where(mad > 1e-9, mad, 1e-9)
            grad = (grad - med) / (1.4826 * mad)
        score = np.linalg.norm(grad, axis=1)
        return score
