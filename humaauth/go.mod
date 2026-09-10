// Module humaauth merges the Auth-All API into a huma document.
//
// It is a separate module, because HC-03 forbids a huma requirement in the
// core module.
module github.com/alternayte/auth-all/humaauth

go 1.25.0

require github.com/alternayte/auth-all v0.0.0

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.57.0 // indirect
)

require (
	github.com/danielgtaylor/huma/v2 v2.39.1
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/alternayte/auth-all => ../
