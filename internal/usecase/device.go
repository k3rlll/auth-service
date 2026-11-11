package usecase

import (
	"strings"
	"unicode/utf8"

	"auth/internal/domain"
)

const (
	maxDeviceNameLength = 100
	maxUserAgentLength  = 512
)

var deviceTypes = map[string]bool{
	domain.DevicePhone: true, domain.DeviceTablet: true, domain.DeviceDesktop: true,
	domain.DeviceLaptop: true, domain.DeviceWeb: true, domain.DeviceOther: true,
}

// normalizeDevice заполняет пропуски по User-Agent и обрезает слишком длинные поля.
// Клиент может прислать точное имя ("iPhone Алисы"); если не прислал, показываем
// хотя бы "Chrome · Windows", чтобы в списке устройств было понятно, что есть что.
func normalizeDevice(d Device) Device {
	d.UserAgent = truncate(strings.TrimSpace(d.UserAgent), maxUserAgentLength)
	d.Name = truncate(strings.TrimSpace(d.Name), maxDeviceNameLength)
	d.Type = strings.ToLower(strings.TrimSpace(d.Type))

	guessedName, guessedType := guessDevice(d.UserAgent)
	if d.Name == "" {
		d.Name = guessedName
	}
	if !deviceTypes[d.Type] {
		d.Type = guessedType
	}
	return d
}

// guessDevice - грубое определение устройства по User-Agent. Точное определение
// требует базы сигнатур; для списка устройств этого достаточно.
func guessDevice(ua string) (name, deviceType string) {
	if ua == "" {
		return "Unknown device", domain.DeviceOther
	}

	var os string
	switch {
	case strings.Contains(ua, "iPhone"):
		os, deviceType = "iPhone", domain.DevicePhone
	case strings.Contains(ua, "iPad"):
		os, deviceType = "iPad", domain.DeviceTablet
	case strings.Contains(ua, "Android") && strings.Contains(ua, "Mobile"):
		os, deviceType = "Android", domain.DevicePhone
	case strings.Contains(ua, "Android"):
		os, deviceType = "Android", domain.DeviceTablet
	case strings.Contains(ua, "Windows"):
		os, deviceType = "Windows", domain.DeviceWeb
	case strings.Contains(ua, "Macintosh"):
		os, deviceType = "macOS", domain.DeviceWeb
	case strings.Contains(ua, "Linux"):
		os, deviceType = "Linux", domain.DeviceWeb
	default:
		// Не браузер: curl, мобильное приложение со своим UA и т.п.
		return truncate(strings.SplitN(ua, " ", 2)[0], maxDeviceNameLength), domain.DeviceOther
	}

	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "YaBrowser/"):
		browser = "Yandex Browser"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	if browser == "" {
		return os, deviceType
	}
	return browser + " · " + os, deviceType
}

func truncate(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	return string([]rune(s)[:maxRunes])
}
