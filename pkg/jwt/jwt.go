package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	// "github.com/mailru/easyjson"
	"bytes"
	"strings"
)

var (
	JWTHead    = []byte(`{"alg":"HS256","typ":"JWT"}`)
	JWTHeadB64 = []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`)
	Secret     = []byte(`secret`)
)

type Payload struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	IsPaid bool   `json:"is_paid"`
}

//easyjson:json
type Payload2 struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	IsPaid bool   `json:"is_paid"`
}

func Make(data Payload) (string, error) {

	// Сначала кодируем данные в виде JSON строки
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// По спецификации JWT все части токена должны быть представлены
	// в виде base64url. В стандартную библиотеку go входит такой енкодер
	enc := base64.RawURLEncoding

	// Кодируем переданные данные и заголовок в base64.
	dataB64 := enc.EncodeToString(dataJSON)
	// Head везде будет одинаков, поэтому будем хранить его в константе
	headB64 := enc.EncodeToString(JWTHead)

	// Формируем подпись токена
	sign, err := buildSign(headB64, dataB64)
	if err != nil {
		return "", fmt.Errorf("Build sign error: %w", err)
	}

	// конкатенируем итоговый результат
	return headB64 + "." + dataB64 + "." + sign, nil
}

func MakeFast(data Payload2) (string, error) {

	// Сначала кодируем данные в виде JSON строки
	// dataJSON, err := json.Marshal(data)
	dataJSON, err := data.MarshalJSON()
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding

	dataB64 := make([]byte, enc.EncodedLen(len(dataJSON)))
	enc.Encode(dataB64, dataJSON)

	var res bytes.Buffer
	// Выделим всю необходимую память за одну аллокацию
	// 45 - длинна подписи (43) и двух точек
	res.Grow(len(JWTHeadB64) + len(dataB64) + 45)
	res.Write(JWTHeadB64)
	res.WriteString(".")
	res.Write(dataB64)

	hasher := hmac.New(sha256.New, Secret)
	_, err = hasher.Write(res.Bytes())
	if err != nil {
		return "", err
	}

	signBin := hasher.Sum(nil)
	sign := make([]byte, enc.EncodedLen(len(signBin)))
	enc.Encode(sign, signBin)

	res.WriteString(".")
	res.Write(sign)

	return res.String(), nil
}

func Parse(tok string) (Payload, error) {

	// Распаковываем токен - делим переданную строку на три части
	// Если их не три, то нам передали не правильный токен
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Payload{}, fmt.Errorf("Token '%s' invalid", tok)
	}

	// Проверяем подпись
	sign, err := buildSign(parts[0], parts[1])
	if err != nil {
		return Payload{}, fmt.Errorf("Build sign error: %w", err)
	}
	if sign != parts[2] {
		return Payload{}, fmt.Errorf("Wrong token signature")
	}

	// Декодируем из base64 payload
	dataJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Payload{}, fmt.Errorf("Invalid payload: %w", err)
	}

	// Переводим JSON строку в структуру
	payload := Payload{}
	err = json.Unmarshal(dataJSON, &payload)
	if err != nil {
		return Payload{}, fmt.Errorf("Invalid payload JSON: %w", err)
	}

	return payload, nil
}

func buildSignFast(in string) (string, error) {
	// Подготовим хэш функцию для подписи
	// Она будет основана на алгоритме sha256
	// Ключ для простоты будем хранить в константе
	hasher := hmac.New(sha256.New, Secret)

	// подписываем данные
	_, err := hasher.Write([]byte(in))
	if err != nil {
		return "", err
	}

	// Вычисляем подпись и кодируем ее в base64
	signBin := hasher.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signBin), nil
}

func buildSign(head, payload string) (string, error) {
	// Подготовим хэш функцию для подписи
	// Она будет основана на алгоритме sha256
	// Ключ для простоты будем хранить в константе
	hasher := hmac.New(sha256.New, Secret)

	// конкатенируем через точку head и payload
	// эти данные мы будем подписывать
	_, err := hasher.Write([]byte(head + "." + payload))
	if err != nil {
		return "", err
	}

	// Вычисляем подпись и кодируем ее в base64
	signBin := hasher.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signBin), nil
}
