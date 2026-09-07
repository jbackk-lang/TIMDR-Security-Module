"""
timdr_rhythm.py — TIMDR Rhythm Analyzer
==========================================
Wykrywanie periodyczności / beaconingu / rytmicznych wzorców w
dowolnym sygnale: [value] (1D) albo [v1, v2, ..., vk] (wielocechowy,
np. [bytes, connections] z telemetrii sieciowej).

Typowe zastosowanie: wykrywanie beaconingu C2 (malware łączący się z
serwerem kontrolnym w regularnych odstępach) - klasyczna technika w
network security monitoring, komplementarna do timdr_security.py
(anomalie amplitudy) i timdr_server.py (powolny dryf/trend).
"""

import numpy as np


class TIMDRRhythm:
    """
    - autocorr: znormalizowana autokorelacja sygnału dla lagów 0..max_lag
    - dominant_periods: lokalne maksima autokorelacji ponad progiem mocy
    - beacon_score: (dominant_periods, global_score) - podsumowanie
    """

    def __init__(self, max_lag=128, min_period=3, power_thresh=0.4):
        """
        max_lag: maksymalny lag autokorelacji (w próbkach)
        min_period: minimalna liczba próbek na okres (filtruje szum)
        power_thresh: próg "mocy rytmu" (0..1) względem maksimum
        """
        self.max_lag = max_lag
        self.min_period = min_period
        self.power_thresh = power_thresh

    # -----------------------------
    # Przygotowanie sygnału
    # -----------------------------
    def _prepare_signal(self, x):
        """
        POPRAWKA (bug skali cech): oryginalny kod dla sygnału
        wielocechowego liczył `np.linalg.norm(x, axis=1)` na SUROWYCH
        wartościach - dokładnie ten sam błąd co wcześniej znaleziony w
        timdr_security.py (anomaly_score): cecha o większej skali
        bezwzględnej (np. `bytes` w setkach/tysiącach) zdominowała normę
        i zagłuszyła rytm obecny w cesze o mniejszej skali (np.
        `connections` w pojedynkach).

        Zweryfikowano: sygnał 2-cechowy [bytes (szum, skala ~1000),
        connections (czysty beacon co 15 próbek, skala 0/1)] - na
        POŁĄCZONYM sygnale (norma z surowych wartości) dominujący
        wykryty okres to lag=48 (power=1.0, artefakt szumu bytes), a
        prawdziwy beacon (lag=15) spadał na power=0.75 - błędnie
        NIE-dominujący. Analizując samo `connections` (bez zaszumienia
        przez `bytes`), lag=15 poprawnie wychodzi jako dominujący
        (power=1.0).

        Naprawiono: każda cecha jest najpierw znormalizowana (z-score:
        odjęcie średniej, podzielenie przez odch. std; przy std≈0 -
        cecha stała, bez wariancji - pomijana, tj. traktowana jako
        zero), dopiero potem liczona jest norma L2 wektora cech na
        każdym kroku czasowym. Dzięki temu żadna pojedyncza cecha nie
        dominuje tylko dlatego, że ma większą skalę bezwzględną.

        Uczciwe zastrzeżenie: norma L2 jest z definicji nieujemna, więc
        nawet po tej poprawce sygnał wielocechowy jest rektyfikowany
        (traci znak) - dla czysto sinusoidalnego rytmu w jednej
        znaczącej kolumnie oznacza to, że autokorelacja wykryje też
        "widmo lustrzane" przy okresie o połowę krótszym (|sin| ma
        okres T/2, nie T). Dla prawdziwej telemetrii sieciowej
        (nieregularne, ostre impulsy typu beacon) to zwykle nie
        przeszkadza - ale przy interpretacji wyników z wieloma cechami
        warto sprawdzić też okres o połowę krótszy od zgłoszonego.
        """
        x = np.asarray(x, dtype=float)
        if x.ndim == 1:
            return x

        out = np.zeros(x.shape[0], dtype=float)
        for col in range(x.shape[1]):
            feature = x[:, col]
            std = np.std(feature)
            if std > 1e-12:
                out += ((feature - np.mean(feature)) / std) ** 2
            # cecha bez wariancji (stała) nie wnosi nic do rytmu - pomijamy
        return np.sqrt(out)

    # -----------------------------
    # Autokorelacja
    # -----------------------------
    def autocorr(self, x):
        """
        Zwraca autokorelację znormalizowaną (max = 1) dla lagów 0..max_lag.

        POPRAWKA (bug obciążonego estymatora): oryginalny kod liczył
        `np.correlate(x, x, mode="full")` i dzielił KAŻDY lag przez tę
        samą stałą `ac[0]` (energię całego sygnału), nie korygując
        malejącej liczby nakładających się próbek przy rosnącym lagu
        (przy lagu L nakłada się tylko n-L próbek, nie n). To systematycznie
        zaniża moc rytmu przy dłuższych okresach - nawet dla idealnie
        periodycznego sygnału bez żadnego szumu.

        Zweryfikowano: czysta fala sinusoidalna o okresie 20 próbek,
        200 próbek długości (10 pełnych okresów) - teoretycznie piki
        autokorelacji przy lag=20,40,60,80,100 powinny mieć TĘ SAMĄ
        wysokość (~1.0, brak szumu). Oryginalny kod dawał 0.90, 0.80,
        0.70, 0.60, 0.50 - liniowy spadek dokładnie zgodny z (n-lag)/n,
        czysty artefakt malejącego okna nakładania, nie żadna prawdziwa
        utrata periodyczności. Dla detekcji beaconingu to oznacza:
        atakujący łączący się co np. 100 próbek wygląda "słabiej
        rytmicznie" niż łączący się co 20 próbek, WYŁĄCZNIE z powodu
        artefaktu estymatora, nie realnej różnicy w regularności.

        Naprawiono: każdy lag jest najpierw dzielony przez liczbę
        próbek, które faktycznie się nakładają na tym lagu (n-lag) -
        dając średni iloczyn na próbkę, niezależny od lagu - dopiero
        POTEM całość jest normalizowana względem lagu=0. Po poprawce
        powyższy test daje dokładnie 1.0 na wszystkich pięciu lagach.
        """
        x = self._prepare_signal(x)
        n = len(x)
        if n < 2:
            return np.zeros(1)
        x = x - np.mean(x)
        full = np.correlate(x, x, mode="full")
        mid = len(full) // 2
        raw = full[mid:mid + self.max_lag + 1]

        lags = np.arange(len(raw))
        overlap_counts = n - lags
        avg = raw / overlap_counts

        if avg[0] == 0:
            return np.zeros_like(avg)
        return avg / avg[0]

    # -----------------------------
    # Dominujące okresy
    # -----------------------------
    def dominant_periods(self, x):
        """
        Zwraca listę (lag, power) dla lagów o silnej periodyczności.
        lag = liczba próbek, power = moc rytmu (0..1) względem
        najsilniejszego wykrytego piku.
        """
        ac = self.autocorr(x)
        if len(ac) <= self.min_period:
            return []

        ac_no0 = ac.copy()
        ac_no0[0] = 0.0

        peaks = []
        for i in range(1, len(ac_no0) - 1):
            if ac_no0[i] > ac_no0[i - 1] and ac_no0[i] > ac_no0[i + 1]:
                peaks.append(i)
        if not peaks:
            return []

        peaks = [p for p in peaks if p >= self.min_period]
        if not peaks:
            return []

        max_power = max(ac_no0[p] for p in peaks)
        if max_power <= 0:
            return []

        result = []
        for p in peaks:
            power = ac_no0[p] / max_power
            if power >= self.power_thresh:
                result.append((int(p), float(power)))
        return result

    # -----------------------------
    # Podsumowanie
    # -----------------------------
    def beacon_score(self, x):
        """
        Zwraca:
        - dominant_periods: [(lag, power), ...]
        - global_score: max(power) lub 0.0 jeśli brak rytmu
        """
        periods = self.dominant_periods(x)
        if not periods:
            return periods, 0.0
        max_power = max(p[1] for p in periods)
        return periods, max_power
