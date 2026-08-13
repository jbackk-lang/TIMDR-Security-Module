"""
TIMDR Server Module — timdr_server.py
=======================================
Rozszerzenie TIMDR Security Module pod monitoring serwerów
produkcyjnych: metryki systemowe zamiast ruchu sieciowego, plus
detektor POWOLNEGO DRYFU (np. wyciek pamięci), którego detektor
"nagłych zmian" (twist) z definicji nie wykryje.

Wejście: lista punktów [cpu_pct, mem_pct, load_avg, t]
  - cpu_pct, mem_pct: procent wykorzystania (0-100)
  - load_avg: średnie obciążenie (np. Linux load average 1-min)
  - t: sekundy, musi ściśle rosnąć

Ważne: jeśli Twoje metryki pochodzą z licznika monotonicznie rosnącego
(np. node_exporter `_total`, WMI performance counters, `/proc/net/dev`)
NIE wrzucaj ich tu wprost - najpierw przelicz na wartość na sekundę
funkcją `counters_to_rates()` poniżej. Gradient policzony wprost na
rosnącym liczniku jest bliski stałej (nachylenie linii bazowej) i nie
wykrywa realnych anomalii bez tego przeliczenia.
"""

import numpy as np


class TIMDRServer:
    def __init__(self):
        pass

    # ------------------------------------------------------------
    @staticmethod
    def _validate(track, n_cols=4, min_points=2):
        tr = np.asarray(track, dtype=np.float64)
        if tr.ndim != 2 or tr.shape[1] != n_cols:
            raise ValueError(f"track musi mieć kształt (N, {n_cols}), dostano {tr.shape}")
        if len(tr) < min_points:
            raise ValueError(f"track musi mieć co najmniej {min_points} punkty, dostano {len(tr)}")
        t = tr[:, -1]
        if np.any(np.diff(t) <= 0):
            raise ValueError("znaczniki czasu (ostatnia kolumna) muszą być ściśle rosnące (dt > 0)")
        return tr

    @staticmethod
    def _robust_loo_zscore(x):
        x = np.asarray(x, dtype=np.float64)
        n = len(x)
        z = np.zeros(n)
        for i in range(n):
            others = np.delete(x, i)
            med = np.median(others)
            mad = np.median(np.abs(others - med))
            mad = mad if mad > 1e-9 else 1e-9
            z[i] = abs(x[i] - med) / (1.4826 * mad)
        return z

    # ------------------------------------------------------------
    @staticmethod
    def counters_to_rates(counter_series, t, handle_resets=True):
        """
        Przelicza monotonicznie rosnący licznik (np. total bytes since boot
        z node_exporter/WMI) na szereg wartości na sekundę.

        handle_resets=True: ujemny przyrost (licznik spadł - restart
        procesu/usługi/serwera) jest traktowany jako 0 przyrostu zamiast
        dawać fałszywy, ogromny UJEMNY skok "prędkości". To częsty,
        realny błąd w domowej roboty monitoringu: bez tej obsługi restart
        procesu wygląda jak gigantyczna anomalia w drugą stronę.
        """
        counter_series = np.asarray(counter_series, dtype=np.float64)
        t = np.asarray(t, dtype=np.float64)
        if len(counter_series) != len(t):
            raise ValueError("counter_series i t muszą mieć tę samą długość")
        if len(counter_series) < 2:
            raise ValueError("potrzeba co najmniej 2 punktów")
        dt = np.diff(t)
        if np.any(dt <= 0):
            raise ValueError("t musi ściśle rosnąć")
        draw = np.diff(counter_series)
        if handle_resets:
            draw = np.where(draw < 0, 0.0, draw)
        rate = draw / dt
        return np.concatenate([[rate[0]], rate])  # powiel pierwsza wartosc dla wyrownania dlugosci

    # --- 1. TIMDR-flow: gradient zmian metryk serwera ---
    def timdr_flow(self, metrics):
        """metrics: [cpu_pct, mem_pct, load_avg, t] -> gradient v+a wzgledem t"""
        tr = self._validate(metrics)
        vals = tr[:, :3]
        t = tr[:, 3]
        v = np.gradient(vals, t, axis=0)
        a = np.gradient(v, t, axis=0)
        return np.gradient(v + a, t, axis=0)

    # --- 2. Twist: NAGŁE anomalie (skok CPU, obciążenia, pamięci) ---
    def twist(self, metrics, z_thresh=3.5):
        """
        Wykrywa nagłe skoki w cpu/mem/load (robust leave-one-out z-score,
        ten sam mechanizm co poprawiony TIMDRSecurity.twist - patrz tam
        opis bugu samo-zatruwającego się progu, którego to unika).
        Zwraca słownik {"cpu_twist":..., "mem_twist":..., "load_twist":...}.
        """
        tr = self._validate(metrics)
        cpu, mem, load, t = tr[:, 0], tr[:, 1], tr[:, 2], tr[:, 3]

        d_cpu = np.gradient(cpu, t)
        d_mem = np.gradient(mem, t)
        d_load = np.gradient(load, t)

        return {
            "cpu_twist": np.where(self._robust_loo_zscore(d_cpu) > z_thresh)[0],
            "mem_twist": np.where(self._robust_loo_zscore(d_mem) > z_thresh)[0],
            "load_twist": np.where(self._robust_loo_zscore(d_load) > z_thresh)[0],
        }

    # --- 3. Trend: POWOLNY dryf (np. wyciek pamięci) ---
    def trend(self, metrics, window=6, slope_thresh_per_min=None, column=1):
        """
        Wykrywa stopniowy, monotoniczny dryf metryki (domyślnie mem_pct,
        column=1) metodą regresji liniowej w oknie kroczącym.

        DLACZEGO TO JEST POTRZEBNE OSOBNO OD twist(): wyciek pamięci
        rośnie po odrobinę na każdą próbkę (np. +0.4 punktu procentowego
        na próbkę) - każdy pojedynczy krok jest dużo mniejszy niż próg
        "nagłej zmiany", więc twist() z definicji tego nie wykryje,
        nawet jeśli suma zmiany w czasie jest ogromna (np. +11.6pp w 30
        próbkach). Zweryfikowano: syntetyczny wyciek +0.4pp/próbkę przez
        30 próbek - twist() (z domyślnym progiem) nie zgłasza ANI JEDNEGO
        punktu, trend() poprawnie wykrywa stałe dodatnie nachylenie.

        slope_thresh_per_min: próg nachylenia w jednostkach metryki/minutę.
        Domyślnie (None) używany jest próg 1.0 (np. 1 punkt procentowy
        pamięci na minutę) - dostosuj do własnego środowiska, to nie jest
        zwalidowana wartość uniwersalna.

        Zwraca listę słowników {"start_idx", "end_idx", "slope_per_min"}
        dla okien, w których |nachylenie| > próg.
        """
        tr = self._validate(metrics)
        y = tr[:, column]
        t = tr[:, -1]
        if slope_thresh_per_min is None:
            slope_thresh_per_min = 1.0

        n = len(tr)
        if window > n:
            window = n

        flags = []
        for start in range(0, n - window + 1):
            end = start + window
            tw = t[start:end]
            yw = y[start:end]
            # regresja liniowa (najmniejsze kwadraty): y = slope*t + intercept
            A = np.vstack([tw, np.ones_like(tw)]).T
            slope, _ = np.linalg.lstsq(A, yw, rcond=None)[0]
            slope_per_min = slope * 60.0
            if abs(slope_per_min) > slope_thresh_per_min:
                flags.append({
                    "start_idx": start,
                    "end_idx": end - 1,
                    "slope_per_min": float(slope_per_min),
                })
        return flags

    # --- 4. TRM-reduction ---
    def trm_reduce(self, metrics):
        tr = self._validate(metrics)
        vals = tr[:, :3]
        smooth = vals.copy()
        for i in range(1, len(vals) - 1):
            smooth[i] = (vals[i - 1] + vals[i] + vals[i + 1]) / 3.0
        return smooth

    # --- 5. Anomaly score (znormalizowany, tak jak w TIMDRSecurity) ---
    def anomaly_score(self, metrics, normalize=True):
        grad = self.timdr_flow(metrics)
        if normalize:
            med = np.median(grad, axis=0)
            mad = np.median(np.abs(grad - med), axis=0)
            mad = np.where(mad > 1e-9, mad, 1e-9)
            grad = (grad - med) / (1.4826 * mad)
        return np.linalg.norm(grad, axis=1)
