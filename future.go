package certgen

import "time"

// Future is a function for converting the current time to a future time
type Future func(now time.Time) time.Time
