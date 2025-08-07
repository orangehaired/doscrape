package main

import (
	"bytes"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	"io"
	"log"

	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func main() {
	cookieHeader := `EZBookPro.SessionId=bp5evltrxv5vpdw2upsr0gut; _gcl_au=1.1.1922681466.1754590320; _cfuvid=a1SQdQjXBEtVOoSYO9Z3UFNGDzm0m9YKqnFkWCijYrk-1754590319182-0.0.1.1-604800000; cf_clearance=Ifgo0YkPknCDALZuVbkdb96Md7WcbT1XZ5PBbwWIff4-1754590321-1.2.1.1-NaeVgOlENCrJdjb6eMh6uU_RjK_DscXImu7TDd4hFmS0I5m66IuGs4WLfbSW.FSeoKN5ShkS5Vd_rwzL0dyMnnDHmFjzkYgxCxXBe89Cm8pk._OBfAoCLMZ0bACvbBtPWGWoJM.fip6bZS3owRAQqWyYDufVfUZwRDY7l_7_Uf1S_HZ9Qvs7osXlWfky9Sub4QH6mUxEgBhCmiPOM505TOv9HrINbCN4b4ez8qVbZWzlcU_tWqW5B7eZJbBWFZx5; __cf_bm=9Amhh4OndRfV7BP3FNb0vCnfUvpvmWGt.H5kS8qxGLw-1754590314-1.0.1.1-JNII7wQ5ZGjmLiM3eEO.YR2nxARHr_aBR0N352upuEgKzzvrwRe6UToobD.o68v.yFodBT_qCJnCdwMf6YLGrnv76_XAjV3hdC1.9speRYw`
	userAgent := `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36`

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithTimeoutSeconds(30),
		//tls_client.WithProxyUrl("http://wapim_proxy:wapim@37.48.78.144:9000"),
	}
	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		log.Fatal("I couldn't create client:", err)
	}

	payload := []byte(`{
		"p01": [4977, 24734],
		"p02": "08/06/2025",
		"p03": "5:00 AM",
		"p04": "7:00 PM",
		"p05": 0,
		"p06": 4,
		"p07": false
	}`)

	req, err := http.NewRequest(http.MethodPost, "https://verrado.ezlinksgolf.com/api/search/search", bytes.NewReader(payload))
	if err != nil {
		log.Fatal("I couldn't prepare request:", err)
	}

	req.Header = http.Header{
		"accept":                      {"application/json, text/plain, */*"},
		"accept-language":             {"en-US,en;q=0.9,tr;q=0.8,tr-TR;q=0.7"},
		"cache-control":               {"no-cache"},
		"content-type":                {"application/json; charset=UTF-8"},
		"origin":                      {"https://verrado.ezlinksgolf.com"},
		"pragma":                      {"no-cache"},
		"priority":                    {"u=1, i"},
		"referer":                     {"https://verrado.ezlinksgolf.com/index.html"},
		"sec-ch-ua":                   {`"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"`},
		"sec-ch-ua-arch":              {`"arm"`},
		"sec-ch-ua-bitness":           {`"64"`},
		"sec-ch-ua-full-version":      {`"138.0.7204.184"`},
		"sec-ch-ua-full-version-list": {`"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {`""`},
		"sec-ch-ua-platform":          {`"macOS"`},
		"sec-ch-ua-platform-version":  {`"15.1.0"`},
		"sec-fetch-dest":              {"empty"},
		"sec-fetch-mode":              {"cors"},
		"sec-fetch-site":              {"same-origin"},
		"user-agent":                  {userAgent},
		"cookie":                      {cookieHeader},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("I couldn't send reequest:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("I couldn't read response:", err)
	}

	fmt.Println("Status code:", resp.StatusCode)
	fmt.Println("Response body:")
	fmt.Println(string(body[:min(len(body), 500)]))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
