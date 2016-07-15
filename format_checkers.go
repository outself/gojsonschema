package gojsonschema

import (
	"encoding/base64"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	// FormatChecker is the interface all formatters added to FormatCheckerChain must implement
	FormatChecker interface {
		IsFormat(input string) bool
	}

	// FormatCheckerChain holds the formatters
	FormatCheckerChain struct {
		formatters map[string]FormatChecker
	}

	// EmailFormatter verifies email address formats
	EmailFormatChecker struct{}

	// IPV4FormatChecker verifies IP addresses in the ipv4 format
	IPV4FormatChecker struct{}

	// IPV6FormatChecker verifies IP addresses in the ipv6 format
	IPV6FormatChecker struct{}

	// DateTimeFormatChecker verifies date/time formats per RFC3339 5.6
	//
	// Valid formats:
	// 		Partial Time: HH:MM:SS
	//		Full Date: YYYY-MM-DD
	// 		Full Time: HH:MM:SSZ-07:00
	//		Date Time: YYYY-MM-DDTHH:MM:SSZ-0700
	//
	// 	Where
	//		YYYY = 4DIGIT year
	//		MM = 2DIGIT month ; 01-12
	//		DD = 2DIGIT day-month ; 01-28, 01-29, 01-30, 01-31 based on month/year
	//		HH = 2DIGIT hour ; 00-23
	//		MM = 2DIGIT ; 00-59
	//		SS = 2DIGIT ; 00-58, 00-60 based on leap second rules
	//		T = Literal
	//		Z = Literal
	//
	//	Note: Nanoseconds are also suported in all formats
	//
	// http://tools.ietf.org/html/rfc3339#section-5.6
	DateTimeFormatChecker struct{}

	// URIFormatCheckers validates a URI with a valid Scheme per RFC3986
	URIFormatChecker struct{}

	// HostnameFormatChecker validates a hostname is in the correct format
	HostnameFormatChecker struct{}

	// UUIDFormatChecker validates a UUID is in the correct format
	UUIDFormatChecker struct{}

	// RegexFormatChecker validates a regex is in the correct format
	RegexFormatChecker struct{}
)

var (
	// Formatters holds the valid formatters, and is a public variable
	// so library users can add custom formatters
	FormatCheckers = FormatCheckerChain{
		formatters: map[string]FormatChecker{
			"date-time": DateTimeFormatChecker{},
			"hostname":  HostnameFormatChecker{},
			"email":     EmailFormatChecker{},
			"ipv4":      IPV4FormatChecker{},
			"ipv6":      IPV6FormatChecker{},
			"uri":       URIFormatChecker{},
			"uuid":      UUIDFormatChecker{},
			"regex":     UUIDFormatChecker{},
			// additional
			"boolean": BooleanChecker{},
			"int32":   BooleanChecker{},
			"int64":   Int64Checker{},
			"float":   Float32Checker{},
			"float32": Float32Checker{},
			"float64": Float64Checker{},
			"uint64":  Uint64Checker{},
			"uint32":  Uint32Checker{},
			"byte":    Base64ByteChecker{},
			"string":  StringChecker{},
		},
	}

	// Regex credit: https://github.com/asaskevich/govalidator
	rxEmail = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")

	// Regex credit: https://www.socketloop.com/tutorials/golang-validate-hostname
	rxHostname = regexp.MustCompile(`^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)

	rxUUID = regexp.MustCompile("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
)

// Add adds a FormatChecker to the FormatCheckerChain
// The name used will be the value used for the format key in your json schema
func (c *FormatCheckerChain) Add(name string, f FormatChecker) *FormatCheckerChain {
	c.formatters[name] = f

	return c
}

// Remove deletes a FormatChecker from the FormatCheckerChain (if it exists)
func (c *FormatCheckerChain) Remove(name string) *FormatCheckerChain {
	delete(c.formatters, name)

	return c
}

// Has checks to see if the FormatCheckerChain holds a FormatChecker with the given name
func (c *FormatCheckerChain) Has(name string) bool {
	_, ok := c.formatters[name]

	return ok
}

// IsFormat will check an input against a FormatChecker with the given name
// to see if it is the correct format
func (c *FormatCheckerChain) IsFormat(name string, input interface{}) bool {
	f, ok := c.formatters[name]

	if !ok {
		return false
	}

	if !isKind(input, reflect.String) {
		return false
	}

	inputString := input.(string)

	return f.IsFormat(inputString)
}

func (f EmailFormatChecker) IsFormat(input string) bool {
	return rxEmail.MatchString(input)
}

// Credit: https://github.com/asaskevich/govalidator
func (f IPV4FormatChecker) IsFormat(input string) bool {
	ip := net.ParseIP(input)
	return ip != nil && strings.Contains(input, ".")
}

// Credit: https://github.com/asaskevich/govalidator
func (f IPV6FormatChecker) IsFormat(input string) bool {
	ip := net.ParseIP(input)
	return ip != nil && strings.Contains(input, ":")
}

func (f DateTimeFormatChecker) IsFormat(input string) bool {
	formats := []string{
		"15:04:05",
		"15:04:05Z07:00",
		"2006-01-02",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if _, err := time.Parse(format, input); err == nil {
			return true
		}
	}

	return false
}

func (f URIFormatChecker) IsFormat(input string) bool {
	u, err := url.Parse(input)
	if err != nil || u.Scheme == "" {
		return false
	}

	return true
}

func (f HostnameFormatChecker) IsFormat(input string) bool {
	return rxHostname.MatchString(input) && len(input) < 256
}

func (f UUIDFormatChecker) IsFormat(input string) bool {
	return rxUUID.MatchString(input)
}

// IsFormat implements FormatChecker interface.
func (f RegexFormatChecker) IsFormat(input string) bool {
	if input == "" {
		return true
	}
	_, err := regexp.Compile(input)
	if err != nil {
		return false
	}
	return true
}

type BooleanChecker struct{}

func (f BooleanChecker) IsFormat(input string) bool {
	_, err := strconv.ParseBool(input)
	return err == nil
}

type StringChecker struct{}

func (f StringChecker) IsFormat(input string) bool {
	return true
}

type Int32Checker struct{}

func (f Int32Checker) IsFormat(input string) bool {
	_, ok := strconv.ParseInt(input, 0, 32)
	return ok == nil
}

type Int64Checker struct{}

func (f Int64Checker) IsFormat(input string) bool {
	_, ok := strconv.ParseInt(input, 0, 64)
	return ok == nil
}

type Base64ByteChecker struct{}

func (f Base64ByteChecker) IsFormat(input string) bool {
	_, err := base64.StdEncoding.DecodeString(input)
	return err == nil
}

type Uint64Checker struct{}

func (f Uint64Checker) IsFormat(input string) bool {
	_, err := strconv.ParseUint(input, 0, 64)
	return err == nil
}

type Uint32Checker struct{}

func (f Uint32Checker) IsFormat(input string) bool {
	_, err := strconv.ParseUint(input, 0, 32)
	return err == nil
}

type Float32Checker struct{}

func (f Float32Checker) IsFormat(input string) bool {
	_, err := strconv.ParseFloat(input, 32)
	return err == nil
}

type Float64Checker struct{}

func (f Float64Checker) IsFormat(input string) bool {
	_, err := strconv.ParseFloat(input, 64)
	return err == nil
}
