"""Pure DSP functions for HackRF .cff captures (int8 I/Q interleaved, no header).

Canonical copy of the parser logic that started as C:\\Users\\Sammi\\temp\\fsk_parser.py
(frozen there with a pointer to this module). Frequency-agnostic: all processing
runs in baseband relative to the capture center; the profile only labels the
result and sanity-checks the declared hardware range (Mayhem HackRF/SDR mode =
1 MHz - 6 GHz).

No __main__, no printing: analyze() returns a JSON-serializable dict so the
dashboard handler (backend/tools/rf.py) stays thin.
"""
import numpy as np

# Band profiles: name -> (center frequency Hz, note). Metadata + sanity only.
PROFILES: dict = {
    'keycard-433.92': (433_920_000, 'llave Sandero III 2022 (dataset propio)'),
    'subghz-315':     (315_000_000, 'ISM 300-348 MHz EU'),
    'subghz-434.42':  (434_420_000, 'ISM 433-434 MHz EU extremo alt'),
    'subghz-868.3':   (868_310_000, 'SRD 868-870 MHz EU'),
    'subghz-915':     (915_000_000, 'ISM 902-928 MHz US'),
    'wifi-2400':      (2_400_000_000, 'WiFi ch1 2.4 GHz (espectro crudo, no demod)'),
    'wifi-2442':      (2_442_000_000, 'WiFi ch13 2.4 GHz (espectro crudo, no demod)'),
    'wifi-5180':      (5_180_000_000, 'WiFi 5 GHz (espectro crudo, no demod)'),
}

# Rango por defecto: HackRF Portapack Mayhem en modo HackRF/SDR = 1 MHz - 6 GHz.
# El parser NO impone un rango: solo avisa si la frecuencia esta fuera del rango
# declarado por el usuario (por defecto este, o --hw-range LO-HI).
HW_RANGE_DEFAULT = (1e6, 6e9)


def hw_range_from_str(s):
    lo_s, hi_s = s.split('-')
    return float(lo_s), float(hi_s)


def load_cff(path):
    raw = open(path, 'rb').read()
    d = np.frombuffer(raw, dtype=np.int8)
    n = len(d) // 2
    i = d[0::2].astype(np.float32)
    q = d[1::2].astype(np.float32)
    return i[:n], q[:n]


def dc_report(i, q):
    """Nivel DC en baseband: pico de la FFT en offset 0 vs resto (dB rel)."""
    x = (i + 1j * q).astype(np.complex128)
    N = len(x)
    S = np.abs(np.fft.fft(x * np.hanning(N)))
    pk = S.max() or 1.0
    return float(20 * np.log10(S[0] / pk)), float(np.mean(x.real)), float(np.mean(x.imag))


def envelope(i, q, sr, win_s=0.010):
    """Env |I| por ventana; umbral documentado: max(4*mediana, 20)."""
    mag = np.hypot(i, q)
    w = int(sr * win_s)
    W = len(mag) // w
    pw = mag[:W*w].reshape(W, w).mean(axis=1)
    med = float(np.median(pw))
    thr = max(med * 4.0, 20.0)
    return mag, pw, w, W, med, thr


def detect_packets(pw, thr, w_ms):
    """Grupos de ventanas activas (con muestreo fino si hay relleno)."""
    act = pw > thr
    if not act.any():
        return []
    idx = np.where(act)[0]
    # dividir por huecos >= 3 ven o bajadas bajo umbral bajo
    low_thr = max(2.0 * float(np.median(pw[pw > 0])) if (pw > 0).any() else 8.0, 8.0)
    groups = np.split(idx, np.where(np.diff(idx) > 1)[0] + 1)
    packets = []
    for g in groups:
        seg = pw[g[0]:g[-1]+1]
        dips = np.where(seg < low_thr)[0]
        if len(dips) == 0:
            packets.append((int(g[0]), int(g[-1])))
            continue
        # split en tramos entre dips (min 3 ven de relleno para contar como hueco real)
        cuts = np.split(np.arange(len(seg)), [d + 1 for d in dips])
        for c in cuts:
            if len(c) >= 2:  # paquete minimo ~20 ms a 10 ms/ven
                packets.append((int(g[0] + c[0]), int(g[-1] - (len(seg) - 1 - c[-1]))))
    return [(a, b) for a, b in packets if b >= a]


def packet_spectrum(x, sr):
    """Top offsets (kHz desde centro, signos reales), clusters de 500 Hz.
    Excluye DC. El par FSK real puede ir a ambos lados del centro
    (p.ej. +42.2 / -34.6 kHz): se busca en espectro completo."""
    N = len(x)
    X = np.fft.fft((x * np.hanning(N)).astype(np.complex128))
    S = np.abs(X) ** 2
    freq = np.fft.fftfreq(N, 1.0/sr) / 1e3
    order = np.argsort(S)[::-1]
    pk = S[order[0]] or 1.0
    clusters = []
    for k in order:
        f = float(freq[k])
        if abs(f) < 2.0:
            continue  # zona DC/fuga
        db = 10 * np.log10(S[k] / pk)
        for c in clusters:
            if abs(c['f'] - f) <= 0.5:
                if db > c['db']:
                    c['f'], c['db'] = f, float(db)
                break
        else:
            clusters.append({'f': f, 'db': float(db)})
    return sorted(clusters, key=lambda c: -c['db'])[:8]


def _mix_lp(x, f, sr, bw):
    """Mezcla a 0 Hz + lowpass por enmascarado FFT (manten |offset| < bw)."""
    y = x.astype(np.complex128) * np.exp(-2j * np.pi * f * np.arange(len(x)) / sr)
    Y = np.fft.fft(y)
    freq = np.fft.fftfreq(len(x), 1.0/sr)
    m = np.abs(freq) <= bw
    return np.fft.ifft(Y * m)


def core_region(seg, sr, low_thr):
    """Recorte de bordes: tramo donde |x| suavizada (200 us) > low_thr."""
    w2 = max(1, int(200e-6 * sr))
    env = np.abs(seg)
    K = len(env) // w2
    e = env[:K*w2].reshape(K, -1).mean(axis=1)
    act = np.where(e > low_thr)[0]
    if len(act) == 0:
        return 0, len(seg)
    return int(act[0] * w2), int((act[-1] + 1) * w2)


def demod_packet(x, fa, fb, Ts, sr):
    """Devuelve (bits, Ea, Eb). Tono B (el mas agudo) = '1', tono A = '0'."""
    bw = max(2000.0, 0.6 / max(Ts, 1e-4))
    ya = _mix_lp(x, fa, sr, bw)
    yb = _mix_lp(x, fb, sr, bw)
    Ea = np.abs(ya); Eb = np.abs(yb)
    n_sym = int(len(Ea) // (Ts * sr))
    if n_sym < 4:
        return None, None, None
    Ea_w = Ea[:n_sym*int(Ts*sr)].reshape(n_sym, -1).mean(axis=1)
    Eb_w = Eb[:n_sym*int(Ts*sr)].reshape(n_sym, -1).mean(axis=1)
    bits = ''.join('1' if b > a else '0' for a, b in zip(Ea_w, Eb_w))
    return bits, Ea_w, Eb_w


def search_Ts(x, fa, fb, sr):
    """Busca Ts por contraste |Ea-Eb| normalizado (cumsum para O(1) por ventana)."""
    bw = 4000.0
    ya = _mix_lp(x, fa, sr, bw); yb = _mix_lp(x, fb, sr, bw)
    Ea = np.abs(ya); Eb = np.abs(yb)
    cEa = np.concatenate([[0], np.cumsum(Ea)]); cEb = np.concatenate([[0], np.cumsum(Eb)])
    best = (None, -1.0)
    for Ts in np.logspace(np.log10(60e-6), np.log10(2e-3), 80):
        n = int(Ts * sr)
        if n < 4 or len(Ea) // n < 4:
            continue
        k = int(len(Ea) // n)
        Ea_w = (cEa[n:(k+1)*n:n] - cEa[0:k*n:n]) / n
        Eb_w = (cEb[n:(k+1)*n:n] - cEb[0:k*n:n]) / n
        tot = np.abs(Ea_w + Eb_w).mean() or 1.0
        contrast = float(np.std(np.abs(Ea_w - Eb_w)) / tot)
        if contrast > best[1]:
            best = (float(Ts), contrast)
    return best


def analyze(path: str, sr: int, profile_name: str, max_demod: int = 200) -> dict:
    """Full characterization of a .cff capture (mirrors the CLI pipeline).

    Returns a JSON-serializable dict. code_status:
      - "validado"              stable stream (top count>=3, positional agreement >90%)
      - "pendiente_validacion"  demodulated but not stable (rolling or to refine)
      - None                    no packets / insufficient material
    """
    if profile_name not in PROFILES:
        raise ValueError(f"Unknown profile: {profile_name}")

    i, q = load_cff(path)
    n = len(i)
    x_full = i + 1j * q
    dc_db, _mI, _mQ = dc_report(i, q)
    w_min = int(0.010 * sr)
    if n >= w_min:
        mag, pw, w, W, med, thr = envelope(i, q, sr)
        packets = detect_packets(pw, thr, w / sr)
        floor_med, threshold = round(med, 3), round(thr, 1)
    else:  # archivo mas corto que una ventana de 10 ms: sin deteccion posible
        mag, w = None, 0
        packets = []
        floor_med = threshold = None

    res: dict = {
        "n_samples": int(n),
        "dc_db_rel": round(dc_db, 1),
        "floor_median": floor_med,
        "threshold": threshold,
        "n_packets": len(packets),
    }
    if not packets:
        res["code_status"] = None
        return res

    low_thr = max(2.0 * med, 8.0)

    # espectros por paquete -> tonos dominantes A/B + secundarias
    fa_list, fb_list, secs = [], [], []
    spec_pkts = [p for p in packets if (p[1]-p[0]+1) * w / sr >= 0.02][:60]
    for a, b in spec_pkts:
        seg = x_full[a*w:(b+1)*w]
        s0, s1 = core_region(seg, sr, low_thr)
        seg = (seg[s0:s1] - np.mean(seg[s0:s1])) if s1 - s0 > 200 else seg
        cl = packet_spectrum(seg, sr)
        if len(cl) >= 2:
            fa_list.append(cl[0]['f']); fb_list.append(cl[1]['f'])
            for c in cl[2:]:
                secs.append((c['f'], c['db']))
    if not fa_list:
        res["insufficient"] = True
        res["code_status"] = None
        return res

    fa, fb = float(np.median(fa_list)), float(np.median(fb_list))
    if fa > fb:
        fa, fb = fb, fa
    res["tone_a_khz"] = round(fa, 2)
    res["tone_b_khz"] = round(fb, 2)
    res["sep_khz"] = round(fb - fa, 2)

    # Ts por contraste sobre un paquete de referencia (el mas largo de los primeros 30)
    ref = max(packets[:30], key=lambda p: p[1]-p[0])
    seg = x_full[ref[0]*w:(ref[1]+1)*w]
    s0, s1 = core_region(seg, sr, low_thr)
    seg = seg[s0:s1] - np.mean(seg[s0:s1])
    # NOTA: fa/fb vienen en kHz del espectro; search_Ts/demod_packet esperan Hz
    # (la CLI original pasaba kHz y su demod interna mezclaba a ~DC: bug que
    # el orquestador corrige aqui, las funciones puras conservan su contrato).
    Ts, _contrast = search_Ts(seg.astype(np.complex64), fa * 1e3, fb * 1e3, sr)

    # verificacion cruzada: espaciado de las replicas espectrales (sidebands ±X kHz)
    offs = []
    for f, _db in secs:
        for dom in (fa, fb):
            d = abs(f - dom)
            if 2.0 < d < 20.0:
                offs.append(d)
    ts_rep_us = round(float(1.0 / (float(np.median(offs)) * 1e3)) * 1e6, 1) if offs else None

    res["ts_us"] = float(Ts * 1e6) if Ts else None
    res["ts_replica_us"] = ts_rep_us

    # demodulacion (limitada a max_demod; requiere Ts encontrada)
    streams: dict = {}
    for a, b in packets[:max_demod]:
        if not Ts:
            break
        seg = x_full[a*w:(b+1)*w]
        s0, s1 = core_region(seg, sr, low_thr)
        seg = (seg[s0:s1] - np.mean(seg[s0:s1])) if s1 - s0 > 200 else seg
        bits, _, _ = demod_packet(seg.astype(np.complex64), fa * 1e3, fb * 1e3, Ts, sr)
        if bits is None:
            continue
        streams.setdefault(bits, []).append((a+w)/sr)

    durs = [(b-a+1)*w/sr*1000 for a, b in packets]
    res["packet_dur_ms"] = {
        "med": round(float(np.median(durs)), 1),
        "min": round(min(durs), 1),
        "max": round(max(durs), 1),
    }

    # clusters (gaps entre paquetes)
    gaps = [((packets[k+1][0]-packets[k][1]-1)*w/sr*1000) for k in range(len(packets)-1)]
    if gaps:
        gmed = float(np.median(gaps))
        cl_size, cur = [], 1
        for g in gaps:
            if g < max(250.0, gmed*3):
                cur += 1
            else:
                cl_size.append(cur); cur = 1
        cl_size.append(cur)
        res["clusters"] = {
            "n_groups": len(cl_size),
            "sizes": sorted(set(int(c) for c in cl_size)),
        }
    else:
        res["clusters"] = {"n_groups": 0, "sizes": []}

    # streams unicos (top 16)
    ranked = sorted(streams.items(), key=lambda kv: -len(kv[1]))
    res["streams"] = [
        {'bits': b, 'count': len(ts), 't_first_s': round(float(min(ts)), 3)}
        for b, ts in ranked[:16]
    ]

    # estructura fina: sub-bursts a 100 us (la resolucion real del emisor)
    w3 = int(100e-6 * sr)
    K3 = len(mag) // w3
    env3 = mag[:K3*w3].reshape(K3, -1).mean(axis=1)
    act3 = env3 > thr
    runs3 = []
    kk = 0
    while kk < len(act3):
        if act3[kk]:
            jj = kk
            while jj < len(act3) and act3[jj]:
                jj += 1
            runs3.append((kk, jj))
            kk = jj
        else:
            kk += 1
    sb_dur = [(b - a) * 0.1 for a, b in runs3]
    res["subbursts"] = {
        "n": len(runs3),
        "med_ms": round(float(np.median(sb_dur)), 2) if sb_dur else 0.0,
        "min_ms": round(min(sb_dur), 2) if sb_dur else 0.0,
        "max_ms": round(max(sb_dur), 2) if sb_dur else 0.0,
    }

    # coincidencia posicional (alineado al final) entre los 2 streams dominantes
    agree = None
    if len(ranked) >= 2:
        b1, b2 = ranked[0][0], ranked[1][0]
        L = min(len(b1), len(b2))
        agree = sum(1 for x, y in zip(b1[-L:], b2[-L:]) if x == y) / L * 100
    res["positional_agreement_pct"] = round(float(agree), 1) if agree is not None else None

    # sello de validacion (regla 5: sin capturas propias suficientes no se fija codigo)
    top_count = len(ranked[0][1]) if ranked else 0
    stable = (top_count >= 3) and (agree is not None and agree > 90.0)
    res["code_status"] = "validado" if stable else "pendiente_validacion"
    return res
