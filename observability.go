package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type LogEvent struct {
	Sequence  uint64         `json:"sequence"`
	Time      time.Time      `json:"time"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Component string         `json:"component,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type logSubscriber struct {
	ch chan LogEvent
}

type LogHub struct {
	mu          sync.RWMutex
	buffer      []LogEvent
	start       int
	count       int
	next        uint64
	subscribers map[uint64]*logSubscriber
	nextSub     uint64
}

func NewLogHub(capacity int) *LogHub {
	if capacity < 100 {
		capacity = 100
	}
	return &LogHub{buffer: make([]LogEvent, capacity), subscribers: make(map[uint64]*logSubscriber)}
}

func (h *LogHub) Resize(capacity int) {
	if capacity < 100 {
		capacity = 100
	}
	h.mu.Lock()
	if capacity == len(h.buffer) {
		h.mu.Unlock()
		return
	}
	keep := min(h.count, capacity)
	next := make([]LogEvent, capacity)
	for i := 0; i < keep; i++ {
		source := (h.start + h.count - keep + i) % len(h.buffer)
		next[i] = h.buffer[source]
	}
	h.buffer, h.start, h.count = next, 0, keep
	h.mu.Unlock()
}

func (h *LogHub) Publish(event LogEvent) {
	h.mu.Lock()
	h.next++
	event.Sequence = h.next
	if h.count < len(h.buffer) {
		index := (h.start + h.count) % len(h.buffer)
		h.buffer[index] = event
		h.count++
	} else {
		h.buffer[h.start] = event
		h.start = (h.start + 1) % len(h.buffer)
	}
	for _, sub := range h.subscribers {
		select {
		case sub.ch <- event:
		default:
			// A slow browser must never block request processing. Its reconnect
			// cursor will make the gap visible on the next subscription.
		}
	}
	h.mu.Unlock()
}

func (h *LogHub) Recent(after uint64, limit int) ([]LogEvent, bool) {
	if limit < 1 || limit > len(h.buffer) {
		limit = len(h.buffer)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	oldest := uint64(0)
	if h.count > 0 {
		oldest = h.buffer[h.start].Sequence
	}
	gap := after > 0 && oldest > 0 && after+1 < oldest
	out := make([]LogEvent, 0, min(limit, h.count))
	for i := 0; i < h.count; i++ {
		event := h.buffer[(h.start+i)%len(h.buffer)]
		if event.Sequence > after {
			out = append(out, event)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, gap
}

func (h *LogHub) Subscribe() (<-chan LogEvent, func()) {
	h.mu.Lock()
	h.nextSub++
	id := h.nextSub
	sub := &logSubscriber{ch: make(chan LogEvent, 128)}
	h.subscribers[id] = sub
	h.mu.Unlock()
	return sub.ch, func() {
		h.mu.Lock()
		delete(h.subscribers, id)
		h.mu.Unlock()
	}
}

type SecretRedactor struct {
	values atomic.Value
}

func NewSecretRedactor() *SecretRedactor {
	r := &SecretRedactor{}
	r.values.Store([]string(nil))
	return r
}

func (r *SecretRedactor) Replace(cfg Config) {
	values := make([]string, 0, len(cfg.ServerKeys)+len(cfg.ZenKeys)+len(cfg.GoKeys)+2)
	values = append(values, cfg.ServerKeys...)
	values = append(values, cfg.ZenKeys...)
	values = append(values, cfg.GoKeys...)
	if cfg.WebUI.Password != "" {
		values = append(values, cfg.WebUI.Password)
	}
	for _, value := range []string{cfg.Upstream.Zen, cfg.Upstream.Go} {
		if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
			values = append(values, value, parsed.User.Username())
			if password, ok := parsed.User.Password(); ok {
				values = append(values, password)
			}
		}
	}
	for _, value := range cfg.RuntimeProxies() {
		if value != "direct" {
			values = append(values, value)
			if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
				values = append(values, parsed.User.Username())
				if password, ok := parsed.User.Password(); ok {
					values = append(values, password)
				}
			}
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	r.values.Store(values)
}

func (r *SecretRedactor) String(value string) string {
	for _, secret := range r.values.Load().([]string) {
		if len(secret) >= 4 {
			value = strings.ReplaceAll(value, secret, "***")
		}
	}
	return value
}

type hubHandler struct {
	base     slog.Handler
	hub      *LogHub
	redactor *SecretRedactor
	attrs    []slog.Attr
	groups   []string
}

func NewStructuredLogger(level *slog.LevelVar, hub *LogHub, redactor *SecretRedactor) *slog.Logger {
	return newStructuredLogger(os.Stdout, level, hub, redactor)
}

func newStructuredLogger(output io.Writer, level *slog.LevelVar, hub *LogHub, redactor *SecretRedactor) *slog.Logger {
	base := slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level, ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
		return sanitizeLogAttr(redactor, attr)
	}})
	return slog.New(&hubHandler{base: base, hub: hub, redactor: redactor})
}

func sanitizeLogAttr(redactor *SecretRedactor, attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	lower := strings.ToLower(attr.Key)
	if strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "secret") {
		return slog.String(attr.Key, "***")
	}
	switch attr.Value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(redactor.String(attr.Value.String()))
	case slog.KindAny:
		if err, ok := attr.Value.Any().(error); ok {
			attr.Value = slog.StringValue(redactor.String(err.Error()))
		}
	}
	return attr
}

func (h *hubHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

func (h *hubHandler) Handle(ctx context.Context, record slog.Record) error {
	if err := h.base.Handle(ctx, record); err != nil {
		return err
	}
	fields := make(map[string]any, record.NumAttrs()+len(h.attrs))
	for _, attr := range h.attrs {
		h.addAttr(fields, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		h.addAttr(fields, attr)
		return true
	})
	component, _ := fields["component"].(string)
	delete(fields, "component")
	h.hub.Publish(LogEvent{
		Time:      record.Time.UTC(),
		Level:     strings.ToLower(record.Level.String()),
		Message:   h.redactor.String(record.Message),
		Component: component,
		Fields:    fields,
	})
	return nil
}

func (h *hubHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.base = h.base.WithAttrs(attrs)
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &clone
}

func (h *hubHandler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.base = h.base.WithGroup(name)
	clone.groups = append(append([]string(nil), h.groups...), name)
	return &clone
}

func (h *hubHandler) addAttr(fields map[string]any, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	key := attr.Key
	if len(h.groups) > 0 {
		key = strings.Join(append(append([]string(nil), h.groups...), key), ".")
	}
	lower := strings.ToLower(key)
	if strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "secret") {
		fields[key] = "***"
		return
	}
	var value any
	switch attr.Value.Kind() {
	case slog.KindString:
		value = h.redactor.String(attr.Value.String())
	case slog.KindInt64:
		value = attr.Value.Int64()
	case slog.KindUint64:
		value = attr.Value.Uint64()
	case slog.KindFloat64:
		value = attr.Value.Float64()
	case slog.KindBool:
		value = attr.Value.Bool()
	case slog.KindDuration:
		value = attr.Value.Duration().String()
	case slog.KindTime:
		value = attr.Value.Time().UTC()
	default:
		value = h.redactor.String(fmt.Sprint(attr.Value.Any()))
	}
	fields[key] = value
}

type requestMeta struct {
	Model    string
	Tier     string
	Request  string
	Attempts int
	Stream   bool
	// Keys counts upstream attempts per "tier:key-fingerprint". Only
	// fingerprints are stored (never credentials) and retries are counted
	// because every attempt consumes upstream quota.
	Keys map[string]int
}

type requestMetaKey struct{}

func metaFromRequest(r *http.Request) *requestMeta {
	meta, _ := r.Context().Value(requestMetaKey{}).(*requestMeta)
	return meta
}

type metricBucket struct {
	minute    int64
	total     uint64
	success   uint64
	errors    uint64
	duration  uint64
	histogram [11]uint64
	endpoints map[string]uint64
	models    map[string]uint64
	tiers     map[string]uint64
	statuses  map[string]uint64
	keys      map[string]uint64
}

func (b *metricBucket) reset(minute int64) {
	*b = metricBucket{
		minute: minute, endpoints: make(map[string]uint64), models: make(map[string]uint64),
		tiers: make(map[string]uint64), statuses: make(map[string]uint64), keys: make(map[string]uint64),
	}
}

type Monitor struct {
	started       time.Time
	active        atomic.Int64
	activeStreams atomic.Int64
	total         atomic.Uint64
	success       atomic.Uint64
	errors        atomic.Uint64
	mu            sync.Mutex
	buckets       [60]metricBucket
}

func NewMonitor() *Monitor { return &Monitor{started: time.Now().UTC()} }

var latencyBounds = [...]uint64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000}

func (m *Monitor) Record(endpoint string, status int, duration time.Duration, meta *requestMeta) {
	m.total.Add(1)
	if status >= 200 && status < 400 {
		m.success.Add(1)
	} else {
		m.errors.Add(1)
	}
	minute := time.Now().Unix() / 60
	m.mu.Lock()
	bucket := &m.buckets[minute%60]
	if bucket.minute != minute {
		bucket.reset(minute)
	}
	bucket.total++
	if status >= 200 && status < 400 {
		bucket.success++
	} else {
		bucket.errors++
	}
	milliseconds := uint64(max(duration.Milliseconds(), 0))
	bucket.duration += milliseconds
	index := len(latencyBounds)
	for i, bound := range latencyBounds {
		if milliseconds <= bound {
			index = i
			break
		}
	}
	bucket.histogram[index]++
	bucket.endpoints[endpoint]++
	bucket.statuses[fmt.Sprint(status)]++
	if meta != nil {
		if meta.Model != "" {
			bucket.models[meta.Model]++
		}
		if meta.Tier != "" {
			bucket.tiers[meta.Tier]++
		}
		for keyID, count := range meta.Keys {
			bucket.keys[keyID] += uint64(count)
		}
	}
	m.mu.Unlock()
}

type MonitorSnapshot struct {
	StartedAt     time.Time         `json:"started_at"`
	UptimeSeconds int64             `json:"uptime_seconds"`
	Active        int64             `json:"active_requests"`
	ActiveStreams int64             `json:"active_streams"`
	Lifetime      MetricSummary     `json:"lifetime"`
	Window        MetricSummary     `json:"last_hour"`
	Series        []MetricSeries    `json:"series"`
	Endpoints     map[string]uint64 `json:"endpoints"`
	Models        map[string]uint64 `json:"models"`
	Tiers         map[string]uint64 `json:"tiers"`
	Statuses      map[string]uint64 `json:"statuses"`
	Keys          map[string]uint64 `json:"keys"`
}

type MetricSummary struct {
	Total       uint64  `json:"total"`
	Success     uint64  `json:"success"`
	Errors      uint64  `json:"errors"`
	SuccessRate float64 `json:"success_rate"`
	AverageMS   float64 `json:"average_ms,omitempty"`
	P50MS       uint64  `json:"p50_ms,omitempty"`
	P95MS       uint64  `json:"p95_ms,omitempty"`
	P99MS       uint64  `json:"p99_ms,omitempty"`
}

type MetricSeries struct {
	Minute  time.Time `json:"minute"`
	Total   uint64    `json:"total"`
	Success uint64    `json:"success"`
	Errors  uint64    `json:"errors"`
}

func (m *Monitor) Snapshot() MonitorSnapshot {
	nowMinute := time.Now().Unix() / 60
	window := MetricSummary{}
	var histogram [11]uint64
	endpoints, models, tiers, statuses, keys := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	series := make([]MetricSeries, 0, 60)
	m.mu.Lock()
	for offset := int64(59); offset >= 0; offset-- {
		minute := nowMinute - offset
		bucket := &m.buckets[minute%60]
		entry := MetricSeries{Minute: time.Unix(minute*60, 0).UTC()}
		if bucket.minute == minute {
			entry.Total, entry.Success, entry.Errors = bucket.total, bucket.success, bucket.errors
			window.Total += bucket.total
			window.Success += bucket.success
			window.Errors += bucket.errors
			window.AverageMS += float64(bucket.duration)
			for i := range histogram {
				histogram[i] += bucket.histogram[i]
			}
			mergeCounts(endpoints, bucket.endpoints)
			mergeCounts(models, bucket.models)
			mergeCounts(tiers, bucket.tiers)
			mergeCounts(statuses, bucket.statuses)
			mergeCounts(keys, bucket.keys)
		}
		series = append(series, entry)
	}
	m.mu.Unlock()
	if window.Total > 0 {
		window.SuccessRate = float64(window.Success) / float64(window.Total)
		window.AverageMS /= float64(window.Total)
		window.P50MS = histogramPercentile(histogram, window.Total, 0.50)
		window.P95MS = histogramPercentile(histogram, window.Total, 0.95)
		window.P99MS = histogramPercentile(histogram, window.Total, 0.99)
	}
	lifetime := MetricSummary{Total: m.total.Load(), Success: m.success.Load(), Errors: m.errors.Load()}
	if lifetime.Total > 0 {
		lifetime.SuccessRate = float64(lifetime.Success) / float64(lifetime.Total)
	}
	return MonitorSnapshot{
		StartedAt: m.started, UptimeSeconds: int64(time.Since(m.started).Seconds()), Active: m.active.Load(),
		ActiveStreams: m.activeStreams.Load(), Lifetime: lifetime, Window: window, Series: series,
		Endpoints: endpoints, Models: models, Tiers: tiers, Statuses: statuses, Keys: keys,
	}
}

func mergeCounts(target, source map[string]uint64) {
	for key, value := range source {
		target[key] += value
	}
}

func histogramPercentile(histogram [11]uint64, total uint64, percentile float64) uint64 {
	target := uint64(float64(total)*percentile + 0.999)
	var count uint64
	for i, value := range histogram {
		count += value
		if count >= target {
			if i < len(latencyBounds) {
				return latencyBounds[i]
			}
			return latencyBounds[len(latencyBounds)-1] + 1
		}
	}
	return 0
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func monitorMiddleware(monitor *Monitor, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		meta := &requestMeta{}
		r = r.WithContext(context.WithValue(r.Context(), requestMetaKey{}, meta))
		writer := &statusWriter{ResponseWriter: w}
		monitor.active.Add(1)
		defer func() {
			monitor.active.Add(-1)
			status := writer.status
			if status == 0 {
				status = http.StatusOK
			}
			duration := time.Since(started)
			// Health checks are infrastructure noise: keep the log (at debug level)
			// but exclude them from request statistics so the dashboard only
			// reflects real API traffic.
			if r.URL.Path == "/healthz" {
				logger.Debug("request completed", "component", "http", "event", "request_complete", "method", r.Method,
					"path", r.URL.Path, "status", status, "duration_ms", duration.Milliseconds(), "bytes", writer.bytes,
					"request_id", meta.Request, "model", meta.Model, "tier", meta.Tier, "attempts", meta.Attempts, "stream", meta.Stream)
				return
			}
			monitor.Record(r.URL.Path, status, duration, meta)
			logger.Info("request completed", "component", "http", "event", "request_complete", "method", r.Method,
				"path", r.URL.Path, "status", status, "duration_ms", duration.Milliseconds(), "bytes", writer.bytes,
				"request_id", meta.Request, "model", meta.Model, "tier", meta.Tier, "attempts", meta.Attempts, "stream", meta.Stream)
		}()
		next.ServeHTTP(writer, r)
	})
}

func setLogLevel(level *slog.LevelVar, value string) {
	switch value {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
}

func encodeSSE(w http.ResponseWriter, event string, id uint64, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if id > 0 {
		_, _ = fmt.Fprintf(w, "id: %d\n", id)
	}
	if event != "" {
		_, _ = fmt.Fprintf(w, "event: %s\n", event)
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", data)
	return err
}
