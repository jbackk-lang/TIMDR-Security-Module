# ============================================
# TIMDR Security Trigger Module
# ============================================
#
# ROLA: czujnik naruszeń integralności TIMDR — NIE model, NIE walidator.
# Nie liczy własnej statystyki i nie podejmuje decyzji "co jest anomalią" —
# to już robią TIMDRSecurity/TIMDRServer (twist/anomaly_score/trend), moduły
# już przetestowane i naprawione (patrz ich POPRAWKA w docstringach). Jedyna
# robota triggera: odpytać te moduły i powiedzieć, KTÓRY typ sygnału odpalił
# się jako pierwszy i GDZIE — czysty dispatcher, nie druga kopia detekcji.
#
# POPRAWKA (ten plik nigdy nie działał na prawdziwym API): dostarczona wersja
# zakładała, że twist() zwraca LISTĘ słowników (jeden na próbkę) i że
# anomaly_score() zwraca listę słowników z kluczem "z_norm" — w
# rzeczywistości twist() zwraca JEDEN słownik tablic INDEKSÓW
# ({"ratio_twist": [...], "connection_twist": [...]}), a anomaly_score()
# zwraca płaską tablicę liczb. `for idx, tw in enumerate(twists)` iterował
# więc po KLUCZACH słownika (stringach), a `tw.get(...)` i `sc["z_norm"]`
# wywalały się na pierwszym prawdziwym wejściu. Podobnie STRUCTURE sprawdzał
# nieistniejący klucz "bytes_twist" (twist() nigdy go nie zwraca — jest tylko
# ratio_twist i connection_twist), a analyze_server() traktował wynik
# trend() (LISTA słowników, jeden na okno) jak JEDEN słownik
# (`mem_trend["slope_per_min"]` na liście -> TypeError). Wszystko naprawione
# poniżej wołaniami zgodnymi z prawdziwym API modułów.
#
# POPRAWKA #2 (samo-zatruwający się próg w CONTINUITY — ten sam wzorzec bugu
# co w _robust_loo_zscore w timdr_security.py/timdr_server.py): oryginalny
# warunek `delta > max(dt) * 3` sprawdzał TAKŻE największą przerwę względem
# JEJ SAMEJ * 3 — a `x > x*3` dla dodatniego x nigdy nie jest prawdą. Sama
# przerwa, którą reguła miała wykryć, nigdy nie mogła przekroczyć własnego
# progu. Naprawione tym samym leave-one-out, którego reszta repo już używa:
# każda przerwa porównywana do największej z POZOSTAŁYCH przerw, nie do
# samej siebie.
#
# POPRAWKA #3 (martwe parametry konstruktora): `scale_thresh` nigdy nie był
# przekazywany do sec.twist()/srv.twist() (obie wołane bez argumentów progu
# -> zawsze ich WŁASNE domyślne 3.5, niezależnie od tego, co podał caller),
# a `trend_slope_thresh_per_min` nigdy nie trafiał do srv.trend() (zawsze
# domyślne 1.0). Wyglądało to jak konfigurowalne progi, a w praktyce żaden z
# tych dwóch parametrów nic nie zmieniał. Teraz oba są faktycznie przekazywane
# do modułów, które robią realną detekcję.

from enum import Enum
from timdr_security import TIMDRSecurity
from timdr_server import TIMDRServer


class SecurityTriggerType(Enum):
    SCALE = "scale_change"
    STRUCTURE = "pattern_change"
    MODEL_CONFLICT = "model_conflict"
    CONTINUITY = "signal_discontinuity"
    NONE = "none"


class SecurityTriggerResult:
    def __init__(self, triggered=False, trigger_type=SecurityTriggerType.NONE,
                 location=None, message=""):
        self.triggered = triggered
        self.trigger_type = trigger_type
        self.location = location
        self.message = message

    def as_dict(self):
        return {
            "triggered": self.triggered,
            "type": self.trigger_type.value,
            "location": self.location,
            "message": self.message
        }


class TIMDRSecurityTrigger:
    """
    Dispatcher nad TIMDRSecurity + TIMDRServer. Woła ich realne detektory
    (twist/anomaly_score/trend) i zwraca PIERWSZY sygnał, który się odpalił
    — nic więcej. Priorytet: STRUCTURE (kilka sygnałów naraz — silniejszy,
    bardziej wiarygodny dowód niż jeden z osobna, tak jak "rezonans" > pojedyncza
    "anomalia" w całym ekosystemie TIMDR) przed SCALE (jeden sygnał).

    scale_thresh: próg z-score dla nagłych skoków (connections we flow;
    cpu/mem/load w metrics) — przekazywany bezpośrednio do twist().
    anomaly_thresh: próg dla anomaly_score() (niezależny, gradientowy
    detektor flow — łapie to, co twist() przeoczył).
    trend_slope_thresh_per_min: próg nachylenia dla trend() (powolny dryf
    pamięci serwera) — przekazywany bezpośrednio do trend().
    Żaden z tych progów nie jest zwalidowaną wartością uniwersalną (patrz
    ta sama uwaga w trend()) — dostosuj do własnego środowiska.
    """

    def __init__(self,
                 scale_thresh=3.5,
                 anomaly_thresh=3.5,
                 trend_slope_thresh_per_min=1.0):
        self.sec = TIMDRSecurity()
        self.srv = TIMDRServer()
        self.scale_thresh = scale_thresh
        self.anomaly_thresh = anomaly_thresh
        self.trend_slope_thresh_per_min = trend_slope_thresh_per_min
        self.last_result = SecurityTriggerResult()

    # ---------- NETWORK FLOW TRIGGERS ----------

    def analyze_flow(self, flow):
        """flow: list of [bytes_in, bytes_out, connections, t]"""
        twists = self.sec.twist(flow, conns_z_thresh=self.scale_thresh)
        ratio_idx = set(int(i) for i in twists["ratio_twist"])
        conn_idx = set(int(i) for i in twists["connection_twist"])

        both = sorted(ratio_idx & conn_idx)
        if both:
            return self._set_result(
                True, SecurityTriggerType.STRUCTURE, both[0],
                "Combined twist in ratio and connections (pattern change in traffic)."
            )

        combined = ratio_idx | conn_idx
        if combined:
            return self._set_result(
                True, SecurityTriggerType.SCALE, min(combined),
                "Significant change in connections/ratio (potential DDoS / lateral movement)."
            )

        scores = self.sec.anomaly_score(flow)
        for idx, sc in enumerate(scores):
            if sc > self.anomaly_thresh:
                return self._set_result(
                    True, SecurityTriggerType.MODEL_CONFLICT, idx,
                    "Anomaly score exceeds threshold (model vs observed traffic conflict)."
                )

        gap = self._find_sampling_gap(flow)
        if gap is not None:
            return self._set_result(
                True, SecurityTriggerType.CONTINUITY, gap,
                "Irregular sampling / gap in flow (possible logging or sensor issue)."
            )

        return self._set_result(False, SecurityTriggerType.NONE, None,
                                "No security trigger detected in flow.")

    # ---------- SERVER METRICS TRIGGERS ----------

    def analyze_server(self, metrics):
        """metrics: list of [cpu_pct, mem_pct, load_avg, t]"""
        twists = self.srv.twist(metrics, z_thresh=self.scale_thresh)
        cpu_idx = set(int(i) for i in twists["cpu_twist"])
        mem_idx = set(int(i) for i in twists["mem_twist"])
        load_idx = set(int(i) for i in twists["load_twist"])

        both = sorted(cpu_idx & mem_idx)
        if both:
            return self._set_result(
                True, SecurityTriggerType.STRUCTURE, both[0],
                "Combined twist in CPU and memory (pattern change in server behavior)."
            )

        combined = cpu_idx | mem_idx | load_idx
        if combined:
            return self._set_result(
                True, SecurityTriggerType.SCALE, min(combined),
                "Sudden spike in CPU, memory or load (potential overload or attack)."
            )

        # trend() zwraca LISTĘ okien, w których nachylenie przekroczyło próg
        # (może być puste) — nie jeden słownik. Bierzemy najsilniejsze okno.
        mem_trend = self.srv.trend(
            metrics, column=1, slope_thresh_per_min=self.trend_slope_thresh_per_min
        )
        if mem_trend:
            worst = max(mem_trend, key=lambda f: abs(f["slope_per_min"]))
            return self._set_result(
                True, SecurityTriggerType.MODEL_CONFLICT, worst["end_idx"],
                f"Persistent memory trend {worst['slope_per_min']:.2f} pp/min "
                "(possible leak / misbehaving process)."
            )

        gap = self._find_sampling_gap(metrics)
        if gap is not None:
            return self._set_result(
                True, SecurityTriggerType.CONTINUITY, gap,
                "Gap in server metrics (monitoring / exporter issue)."
            )

        return self._set_result(False, SecurityTriggerType.NONE, None,
                                "No security trigger detected in server metrics.")

    # ---------- INTERNAL ----------

    @staticmethod
    def _find_sampling_gap(rows, factor=3.0):
        """
        Integralność SAMPLOWANIA (czy próbki są ciągłe), niezależna od
        wartości sygnału — nie liczy się do "modelu" analogicznie do
        twist()/trend(). Leave-one-out: każda przerwa porównywana do
        największej z POZOSTAŁYCH przerw, nigdy do samej siebie (patrz
        POPRAWKA #2 w nagłówku pliku — bez tego reguła jest strukturalnie
        nieosiągalna dla własnej największej przerwy).
        """
        if len(rows) < 3:
            return None
        times = [row[-1] for row in rows]
        dt = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        for idx, delta in enumerate(dt):
            others = dt[:idx] + dt[idx + 1:]
            if delta > max(others) * factor:
                return idx + 1
        return None

    def _set_result(self, triggered, trigger_type, location, message):
        self.last_result = SecurityTriggerResult(triggered, trigger_type, location, message)
        return self.last_result

    def get_last(self):
        return self.last_result
