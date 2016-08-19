package btce

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

type TradeType string

const (
	Bid TradeType = "bid"
	Ask TradeType = "ask"
)

type Pair string

const (
	BTCUSD Pair = "btc_usd"
	BTCEUR      = "btc_eur"
	BTCRUR      = "btc_rur"
	DSHBTC      = "dsh_btc"
	ETHBTC      = "eth_btc"
	ETHLTC      = "eth_ltc"
	ETHRUR      = "eth_rur"
	ETHUSD      = "eth_usd"
	EURRUR      = "eur_rur"
	EURUSD      = "eur_usd"
	LTCBTC      = "ltc_btc"
	LTCEUR      = "ltc_eur"
	LTCRUR      = "ltc_rur"
	LTCUSD      = "ltc_usd"
	NMCBTC      = "nmc_btc"
	NMCUSD      = "nmc_usd"
	NVCBTC      = "nvc_btc"
	NVCUSD      = "nvc_usd"
	PPCBTC      = "ppc_btc"
	PPCUSD      = "ppc_usd"
	USDRUR      = "usd_rur"
)

// URLs and path to api
//
// It's yours responsibility to end paths with '/' if it's necessary
var (
	BaseURL         = "https://btc-e.nz/"
	InfoPath        = "api/2/"
	TradeAPIv1Path  = "tapi"
	PublicAPIv3Path = "api/3/"
)

var (
	key       string
	secretKey []byte

	nonce uint64
)

// NonceFile is local file to store nonce.
var NonceFile string = ".nonce"

// Time represents server time in seconds since UNIX epoch
type Time int32

type Fee int64

type Bool bool

type Tick struct {
	Low        float64 `json:"low"`
	High       float64 `json:"high"`
	Avg        float64 `json:"avg"`
	Vol        float64 `json:"vol"`
	VolCur     float64 `json:"vol_cur"`
	Last       float64 `json:"last"`
	Buy        float64 `json:"buy"`
	Sell       float64 `json:"sell"`
	Updated    Time    `json:"updated"`
	ServerTime Time    `json:"server_time"`
}

type TicksMap map[Pair]Tick

type TradeInfo struct {
	TID       uint64    `json:"tid"`
	Type      TradeType `json:"type"`
	Price     float64   `json:"price"`
	Amount    float64   `json:"amount"`
	Timestamp Time      `json:"timestamp"`
}

type TradesInfo []TradeInfo

type TradesMap map[Pair]TradesInfo

type DepthItem struct {
	Price  float64
	Volume float64
}

type Depth struct {
	Asks []DepthItem
	Bids []DepthItem
}

type DepthsMap map[Pair]Depth

type Funds map[Pair]float64

type Rights struct {
	Info     Bool
	Trade    Bool
	Withdraw Bool
}

type AccountInfo struct {
	Funds
	Rights
	TransactionCount int  `json:"transaction_count"`
	OpenOrders       int  `json:"open_orders"`
	ServerTime       Time `json:"server_time"`
}

type TradeResult struct {
	Received float64
	Remains  float64
	OrderID  uint64 `json:"order_id"`
	Funds
}

type Order struct {
	Pair
	Type             TradeType
	Amount           float64
	Rate             float64
	TimestampCreated Time `json:"timestamp_created"`
	IsYourOrder      Bool `json:"is_your_order"`
}

type OrdersMap map[uint64]Order

type PairInfo struct {
	DecimapPlaces int     `json:"decimal_places"`
	MinPrice      float64 `json:"min_price"`
	MaxPrice      float64 `json:"max_price"`
	MinAmount     float64 `json:"min_amount"`
	Hidden        Bool
	Fee
}

type PairsMap map[Pair]PairInfo

// SetKeys sets authorization keys to use
func SetKeys(k, secret string) {
	key = k
	var err error
	secretKey, err = hex.DecodeString(secret)
	if err != nil {
		panic(err)
	}
}

// SetNonce sets last used nonce for trade API calls
//
// More info: https://btc-e.nz/tapi/docs#auth
func SetNonce(n uint64) {
	atomic.StoreUint64(&nonce, n)
}

// LoadNonce loads last used nonce from file NonceFile
//
// More info: https://btc-e.nz/tapi/docs#auth
func LoadNonce() {
	data, err := ioutil.ReadAll(NonceFile)
	if err != nil {
		panic(err)
	}
	nonce, err = strconv.ParseUint(string(data), 10, 32)
	if err != nil {
		panic(err)
	}
}

// SaveNonce dumps current nonce value to file NonceFile
//
// More info: https://btc-e.nz/tapi/docs#auth
func SaveNonce() {
	v := atomic.LoadUint64(&nonce)
	err := ioutil.WriteFile(NonceFile, []byte(strconv.FormatUint(v, 10)))
	if err != nil {
		panic(err)
	}
}

func request(params url.Values, res interface{}) error {
	if _, ok := params["nonce"]; !ok {
		n := nextNonce()
		params.Set("nonce", strconv.FormatUint(n, 10))
	}

	encoded := params.Encode()
	req, err := http.NewRequest("POST", BaseURL+TradeAPIv1Path, bytes.NewBufferString(encoded))
	if err != nil {
		return err
	}

	// This line is important
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Key", key)

	{ // sign
		h := hmac.New(sha512.New, []byte(hex.EncodeToString(secretKey)))
		_, _ = h.Write([]byte(encoded))
		sum := h.Sum(nil)
		hsum := hex.EncodeToString(sum)
		req.Header.Set("Sign", hsum)
	}

	resp, err := http.DefaultClient.Do(req)
	//	log.Printf("POST/api [err %v]:\n%v\n%v", err, resp, req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("response body close error: %v", err)
		}
	}()

	var buf bytes.Buffer
	tr := io.TeeReader(resp.Body, &buf)
	dec := json.NewDecoder(tr)
	if err = dec.Decode(res); err != nil {
		return err
	}
	log.Printf("read: %s", buf.Bytes())

	return nil
}

func get(pair Pair, data string, res interface{}) error {
	resp, err := http.Get(BaseURL + InfoPath + string(pair) + "/" + data)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("response body close error: %v", err)
		}
	}()

	var buf bytes.Buffer
	tr := io.TeeReader(resp.Body, &buf)
	dec := json.NewDecoder(tr)
	if err = dec.Decode(res); err != nil {
		return err
	}

	//	log.Printf("read: %s", buf.Bytes())

	return nil
}

func api3(method string, res interface{}, pairs ...Pair) error {
	ps := ""
	if len(pairs) > 0 {
		ss := make([]string, len(pairs))
		for i := range pairs {
			ss[i] = string(pairs[i])
		}
		ps = "/" + strings.Join(ss, "-")
	}
	resp, err := http.Get(BaseURL + PublicAPIv3Path + method + ps)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("response body close error: %v", err)
		}
	}()

	var buf bytes.Buffer
	tr := io.TeeReader(resp.Body, &buf)
	dec := json.NewDecoder(tr)
	if err = dec.Decode(res); err != nil {
		return err
	}

	//	log.Printf("read: %s", buf.Bytes())

	return nil
}

type apiResp struct {
	Success Bool
	Return  interface{}
	Error   string
}

// GetPairs loads list of tradable pairs and info about them.
//
// Implements btc-e public API v3 `info` method.
//
// More info: https://btc-e.com/api/3/docs#info
func GetPairs() (PairsMap, error) {
	var res struct {
		Pairs PairsMap
	}
	err := api3("info", &res)
	if err != nil {
		return nil, err
	}

	return res.Pairs, nil
}

// GetTicks loads last ticks (prices) for specified pairs.
//
// Implements btc-e public API v3 `ticker` method.
//
// More info: https://btc-e.com/api/3/docs#ticker
func GetTicks(pairs ...Pair) (TicksMap, error) {
	var res TicksMap
	if len(pairs) == 0 {
		return res, errors.New("must be one or more pairs")
	}
	err := api3("ticker", &res, pairs...)
	if err != nil {
		return res, err
	}

	return res, nil
}

// GetTrades loads last completed trades.
//
// Implements btc-e public API v3 `trades` method.
//
// More info: https://btc-e.com/api/3/docs#trades
func GetTrades(pairs ...Pair) (TradesMap, error) {
	var res TradesMap
	err := api3("trades", &res, pairs...)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// GetDepths loads prices and amounts of active orders.
//
// Implements btc-e public API v3 `depth` method.
//
// More info: https://btc-e.com/api/3/docs#depth
func GetDepths(pairs ...Pair) (DepthsMap, error) {
	var res DepthsMap
	if len(pairs) == 0 {
		return res, errors.New("must be one or more pairs")
	}
	err := api3("depth", &res, pairs...)
	if err != nil {
		return res, err
	}

	return res, nil
}

// GetTick loads last tick (prices) for specified pair.
// It's wrapper around GetTicks.
//
// Implements btc-e public API v3 `ticker` method.
//
// More info: https://btc-e.com/api/3/docs#ticker
func GetTick(pair Pair) (Tick, error) {
	res, err := GetTicks(pair)
	if err != nil {
		return Tick{}, err
	}
	return res[pair], nil
}

// GetDepth loads proces and volumes of active orders.
// It's wrapper around GetDepths.
//
// Implements btc-e public API v3 `depth` method.
//
// More info: https://btc-e.com/api/3/docs#depth
func GetDepth(pair Pair) (Depth, error) {
	res, err := GetDepths(pair)
	if err != nil {
		return Depth{}, err
	}
	return res[pair], nil
}

// GetInfo loads your account info.
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `getInfo` method.
//
// More info: https://btc-e.nz/tapi/docs#getInfo
func GetInfo() (AccountInfo, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info AccountInfo
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "getInfo")
	if err := request(p, &res); err != nil {
		return info, err
	}
	if res.Error != "" {
		return info, errors.New(res.Error)
	}
	return info, nil
}

// Trade create order or execute it right away.
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `trade` method.
//
// More info: https://btc-e.nz/tapi/docs#Trade
func Trade(pair Pair, tp TradeType, rate, amount float64) (TradeResult, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info TradeResult
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "trade")
	p.Set("pair", string(pair))
	p.Set("type", string(tp))
	p.Set("rate", strconv.FormatFloat(rate, 'f', 6, 64))
	p.Set("amount", strconv.FormatFloat(amount, 'f', 6, 64))
	if err := request(p, &res); err != nil {
		return info, err
	}
	if res.Error != "" {
		return info, errors.New(res.Error)
	}
	return info, nil
}

// ActiveOrders loads list of your active orders.
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `activeOrders` method.
//
// More info: https://btc-e.nz/tapi/docs#ActiveOrders
func ActiveOrders(pair Pair) (OrdersMap, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info OrdersMap
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "activeorders")
	p.Set("pair", string(pair))
	if err := request(p, &res); err != nil {
		return info, err
	}
	if res.Error != "" {
		return info, errors.New(res.Error)
	}
	return info, nil
}

// OrderInfo loads info about your specified order.
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `orderInfo` method.
//
// More info: https://btc-e.nz/tapi/docs#OrderInfo
func OrderInfo(orderID uint64) (OrdersMap, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info OrdersMap
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "orderinfo")
	p.Set("order_id", strconv.FormatUint(orderID, 64))
	if err := request(p, &res); err != nil {
		return info, err
	}
	if res.Error != "" {
		return info, errors.New(res.Error)
	}
	return info, nil
}

// CancelOrder cancels order.
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `cancelOrder` method.
//
// More info: https://btc-e.nz/tapi/docs#CancelOrder
func CancelOrder(orderID uint64) (Funds, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info struct {
		Funds
	}
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "cancelOrder")
	p.Set("order_id", strconv.FormatUint(orderID, 64))
	if err := request(p, &res); err != nil {
		return info.Funds, err
	}
	if res.Error != "" {
		return info.Funds, errors.New(res.Error)
	}
	return info.Funds, nil
}

// TradeHistory loads your completed orders history.
//
// It's don't support any arhuments for now
//
// Panics if key and secret key are not set.
//
// Implements btc-e trade API v1 `tradeHistory` method.
//
// More info: https://btc-e.nz/tapi/docs#TradeHistory
func TradeHistory() (OrdersMap, error) {
	if key == "" {
		panic("key does not provided")
	}
	var info struct {
		Funds
	}
	var res apiResp
	res.Return = &info
	p := url.Values{}
	p.Set("method", "tradeHistory")
	if err := request(p, &res); err != nil {
		return info.Funds, err
	}
	if res.Error != "" {
		return info.Funds, errors.New(res.Error)
	}
	return info.Funds, nil
}

func nextNonce() uint64 {
	return atomic.AddUint64(&nonce, 1)
}

func (f Fee) String() string {
	return strconv.FormatInt(int64(f), 10)
}

func (t Tick) String() string {
	return js(t)
}

func (t TradeInfo) String() string {
	return js(t)
}

func (t TradesInfo) String() string {
	res := ""
	for _, t := range t {
		res += js(t) + "\n"
	}
	return res
}

func (d DepthItem) String() string {
	return fmt.Sprintf("%10.5f %13.3f", d.Price, d.Volume)
}

func (d Depth) String() string {
	const w = 40
	format := fmt.Sprintf("%%%ds %%%ds\n", w, w)
	res := fmt.Sprintf(format, "ASKS", "BIDS")
	i := 0
	for i < len(d.Asks) || i < len(d.Bids) {
		var ask, bid string
		if i < len(d.Asks) {
			ask = d.Asks[i].String()
		} else {
			ask = ""
		}
		if i < len(d.Bids) {
			bid = d.Bids[i].String()
		} else {
			bid = ""
		}
		res += fmt.Sprintf(format, ask, bid)
		i++
	}
	return res
}

// UnmarshalJSON decodes JSON array [<price>, <volume>]
func (d *DepthItem) UnmarshalJSON(data []byte) error {
	var q [2]float64
	if err := json.Unmarshal(data, &q); err != nil {
		return err
	}
	d.Price = q[0]
	d.Volume = q[1]
	return nil
}

func (a AccountInfo) String() string {
	return js(a)
}

func (p PairsMap) String() string {
	return js(p)
}

func js(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return string(data)
}

// UnmarshalJSON decodes JSON int value
func (b *Bool) UnmarshalJSON(data []byte) error {
	var q int
	if err := json.Unmarshal(data, &q); err != nil {
		return err
	}
	*b = q != 0
	return nil
}
