package jwt

import (
	"testing"
)

var data = Payload{
	ID:     1,
	Name:   "Bob",
	IsPaid: true,
}

var data2 = Payload2{
	ID:     1,
	Name:   "Bob",
	IsPaid: true,
}

const (
	Expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6IkJvYiIsImlzX3BhaWQiOnRydWV9.y375jyu94WKXbX__QLQL4cY3109xJZ3gRLoTDfQFx14"
)

func TestJWT(t *testing.T) {
	res, err := MakeFast(data2)
	if err != nil {
		t.Errorf("Make error: %v", err)
	}

	if res != Expected {
		t.Errorf("Got(%s) != Expected(%s)", res, Expected)
		return
	}
}

func BenchmarkJWTFast(b *testing.B) {
	for i := 0; i < b.N; i++ {
		MakeFast(data2)
	}
}

func BenchmarkJWT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Make(data)
	}
}
