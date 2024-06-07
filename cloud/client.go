package cloud

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/scodevn2023/micloud/types"
)

type Client struct {
	country    string
	username   string
	password   string
	deviceID   string
	userAgent  string
	us         *userSecurity
	cookies    []*http.Cookie
	httpClient *http.Client
}

type userSecurity struct {
	Sign         string
	Location     string
	AccessToken  string
	CurrentUserID int64
	UserID       int64
	Security     string
	ServiceToken string
	Timestamp    int64
	DeviceID     string
}

type loginSignResponse struct {
	Sign string `json:"_sign"`
}

type loginInternalResponse struct {
	Code      int    `json:"code"`
	Location  string `json:"location"`
	PassToken string `json:"passToken"`
	CUserId   int64  `json:"cUserId"`
	UserId    int64  `json:"userId"`
	Ssecurity string `json:"ssecurity"`
}

type Response struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
	Error   error
}

type Request struct {
	Method string
	Path   string
	Data   map[string]interface{}
}

func newRequest(path string, data map[string]interface{}) *Request {
	return &Request{
		Method: http.MethodPost,
		Path:   path,
		Data:   data,
	}
}

func (r *Response) IsOK() bool {
	return r.Code == 0
}

func (r *Response) Decode(v interface{}) error {
	return json.Unmarshal(r.Result, v)
}

func New(country, username, password string) *Client {
	return &Client{
		country:  country,
		username: username,
		password: password,
		us:       &userSecurity{},
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *Client) getLoginSign(ctx context.Context) error {
	uri := "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("http response %s", res.Status)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	pos := bytes.IndexByte(buf, '{')
	if pos > -1 {
		buf = buf[pos:]
	}

	ret := &loginSignResponse{}
	if err := json.Unmarshal(buf, ret); err == nil {
		c.us.Sign = ret.Sign
	}
	return nil
}

func (c *Client) loginInternal(ctx context.Context) error {
	uri := "https://account.xiaomi.com/pass/serviceLoginAuth2"
	qs := url.Values{}
	hash := md5.New()
	hash.Write([]byte(c.password))
	qs.Set("sid", "xiaomiio")
	qs.Set("hash", strings.ToUpper(hex.EncodeToString(hash.Sum(nil))))
	qs.Set("callback", "https://sts.api.io.mi.com/sts")
	qs.Set("qs", "%3Fsid%3Dxiaomiio%26_json%3Dtrue")
	qs.Set("user", c.username)
	qs.Set("_sign", c.us.Sign)
	qs.Set("_json", "true")
	uri += "?" + qs.Encode()

	req, err := http.NewRequest(http.MethodPost, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("http response %s", res.Status)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	pos := bytes.IndexByte(buf, '{')
	if pos > -1 {
		buf = buf[pos:]
	}

	ret := &loginInternalResponse{}
	if err := json.Unmarshal(buf, ret); err != nil {
		return err
	}

	if ret.Code == 0 {
		c.us.Location = ret.Location
		c.us.AccessToken = ret.PassToken
		c.us.CurrentUserID = ret.CUserId
		c.us.UserID = ret.UserId
		c.us.Security = ret.Ssecurity
	}
	return nil
}

func (c *Client) getLoginServeToken(ctx context.Context) error {
	req, err := http.NewRequest(http.MethodGet, c.us.Location, nil)
	if err != nil {
		return err
	}
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: c.username})

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	for _, cookie := range res.Cookies() {
		if cookie.Name == "serviceToken" {
			c.us.ServiceToken = cookie.Value
		}
	}
	c.us.Timestamp = time.Now().Unix()
	return nil
}

func (c *Client) buildRequestUri(uri string) string {
	prefix := "https://" + c.country + ".api.io.mi.com/app"
	if c.country == "cn" {
		prefix = "https://api.io.mi.com/app"
	}
	if len(uri) > 0 && uri[0] != '/' {
		uri = "/" + uri
	}
	return prefix + uri
}

func (c *Client) signatureNonce(nonce string) (string, error) {
	b1, err := base64.StdEncoding.DecodeString(c.us.Security)
	if err != nil {
		return "", err
	}
	b2, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return "", err
	}
	buf := sha256.Sum256(append(b1, b2...))
	return base64.StdEncoding.EncodeToString(buf[:]), nil
}

func (c *Client) sha1Signature(method, uri string, qs url.Values, signNonce string) string {
	values := []string{strings.ToUpper(method), strings.TrimPrefix(path.Clean(uri), "/app")}
	for k := range qs {
		values = append(values, fmt.Sprintf("%s=%s", k, qs.Get(k)))
	}
	values = append(values, signNonce)
	hash := sha1.New()
	hash.Write([]byte(strings.Join(values, "&")))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func (c *Client) encodeQueryParams(method, uri string, qs url.Values) (string, url.Values) {
	nonce := make([]byte, 12)
	rand.New(rand.NewSource(time.Now().UnixNano())).Read(nonce)
	binary.BigEndian.PutUint32(nonce[8:], uint32(time.Now().UnixMilli()/60000))
	noncestr := base64.StdEncoding.EncodeToString(nonce)
	signNonce, err := c.signatureNonce(noncestr)
	if err != nil {
		return signNonce, qs
	}
	qs.Set("rc4_hash__", c.sha1Signature(method, uri, qs, signNonce))
	for k := range qs {
		qs.Set(k, c.rc4Encrypt(signNonce, qs.Get(k)))
	}
	qs.Set("signature", c.sha1Signature(method, uri, qs, signNonce))
	qs.Set("ssecurity", c.us.Security)
	qs.Set("_nonce", noncestr)
	return signNonce, qs
}

func (c *Client) rc4Encrypt(signNonce, payload string) string {
	buf, err := base64.StdEncoding.DecodeString(signNonce)
	if err != nil {
		return ""
	}
	cipher, err := rc4.NewCipher(buf)
	if err != nil {
		return ""
	}
	dst := make([]byte, len(payload))
	cipher.XORKeyStream(dst, []byte(payload))
	return base64.StdEncoding.EncodeToString(dst)
}

func (c *Client) rc4Decrypt(signNonce string, payload []byte) ([]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(signNonce)
	if err != nil {
		return nil, err
	}
	cipher, err := rc4.NewCipher(buf)
	if err != nil {
		return nil, err
	}
	dlen := base64.StdEncoding.DecodedLen(len(payload))
	buf = make([]byte, dlen)
	n, err := base64.StdEncoding.Decode(buf, payload)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(buf[:n]))
	cipher.XORKeyStream(dst, buf[:n])
	return dst, nil
}

func (c *Client) doRequest(ctx context.Context, r *Request) *Response {
	ret := &Response{}
	if c.us == nil || c.us.Security == "" || c.us.ServiceToken == "" {
		ret.Error = errors.New("please log in to the system first")
		return ret
	}

	qs := url.Values{}
	if r.Data != nil {
		buf, err := json.Marshal(r.Data)
		if err != nil {
			ret.Error = err
			return ret
		}
		qs.Set("data", string(buf))
	}

	signNonce, qs := c.encodeQueryParams(r.Method, r.Path, qs)
	reqUri := c.buildRequestUri(r.Path) + "?" + qs.Encode()
	req, err := http.NewRequest(r.Method, reqUri, nil)
	if err != nil {
		ret.Error = err
		return ret
	}
	req.Header.Add("Accept-Encoding", "identity")
	req.Header.Add("User-Agent", c.userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header["x-xiaomi-protocal-flag-cli"] = []string{"PROTOCAL-HTTP2"}
	req.Header["MIOT-ENCRYPT-ALGORITHM"] = []string{"ENCRYPT-RC4"}

	req.AddCookie(&http.Cookie{Name: "userId", Value: strconv.FormatInt(c.us.UserID, 10)})
	req.AddCookie(&http.Cookie{Name: "yetAnotherServiceToken", Value: c.us.ServiceToken})
	req.AddCookie(&http.Cookie{Name: "serviceToken", Value: c.us.ServiceToken})
	req.AddCookie(&http.Cookie{Name: "locale", Value: "en_GB"})
	req.AddCookie(&http.Cookie{Name: "timezone", Value: "GMT+02:00"})
	req.AddCookie(&http.Cookie{Name: "is_daylight", Value: "1"})
	req.AddCookie(&http.Cookie{Name: "dst_offset", Value: "3600000"})
	req.AddCookie(&http.Cookie{Name: "channel", Value: "MI_APP_STORE"})

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		ret.Error = fmt.Errorf("http request error: %s", err.Error())
		return ret
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		ret.Code = res.StatusCode
		ret.Error = fmt.Errorf("http server response %d: %s", res.StatusCode, res.Status)
		return ret
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		ret.Error = err
		return ret
	}

	buf, err = c.rc4Decrypt(signNonce, buf)
	if err != nil {
		ret.Error = err
		return ret
	}

	if err := json.Unmarshal(buf, ret); err != nil {
		ret.Error = err
		return ret
	}

	if ret.Code != 0 {
		ret.Error = errors.New(ret.Message)
	}
	return ret
}

func (c *Client) buildUserAgent(deviceID string) string {
	return fmt.Sprintf("Android-7.1.1-1.0.0-ONEPLUS A3010-136-%s APP/xiaomi.smarthome APPV/62830", strings.ToUpper(deviceID))
}

func (c *Client) prepareLogin() {
	c.userAgent = c.buildUserAgent(c.deviceID)
	c.cookies = []*http.Cookie{
		{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "mi.com"},
		{Name: "sdkVersion", Value: "accountsdk-18.8.15", Domain: "xiaomi.com"},
		{Name: "deviceId", Value: c.deviceID, Domain: "mi.com"},
		{Name: "deviceId", Value: c.deviceID, Domain: "xiaomi.com"},
	}
}

func (c *Client) login(ctx context.Context, force bool) error {
	buf := make([]byte, 6)
	rand.New(rand.NewSource(time.Now().UnixNano())).Read(buf)

	if c.us != nil {
		c.us.DeviceID = ""
	}
	c.deviceID = ""
	c.prepareLogin()

	if err := c.getLoginSign(ctx); err != nil {
		return err
	}
	if err := c.loginInternal(ctx); err != nil {
		return err
	}
	if err := c.getLoginServeToken(ctx); err != nil {
		return err
	}

	c.us.DeviceID = c.deviceID
	c.us.Timestamp = time.Now().Unix()
	return nil
}

func (c *Client) Login(ctx context.Context) error {
	return c.login(ctx, false)
}

func (c *Client) HasNewMsg(ctx context.Context) bool {
	ret := c.Request(ctx, newRequest("/v2/message/v2/check_new_msg", map[string]interface{}{"begin_at": time.Now().Unix() - 60}))
	if ret.IsOK() {
		b, _ := strconv.ParseBool(string(ret.Result))
		return b
	}
	return false
}

func (c *Client) GetHomes(ctx context.Context) ([]*MiHome, error) {
	ret := c.Request(ctx, newRequest("/v2/homeroom/gethome", map[string]interface{}{
		"fg":              true,
		"fetch_share":     true,
		"fetch_share_dev": true,
		"limit":           300,
		"app_ver":         7,
	}))
	if !ret.IsOK() {
		return nil, ret.Error
	}
	res := &homeListResponse{}
	if err := ret.Decode(res); err != nil {
		return nil, err
	}
	return res.HomeList, nil
}

func (c *Client) GetHomeDevices(ctx context.Context, homeID int64) ([]*DeviceInfo, error) {
	ret := c.Request(ctx, newRequest("/v2/home/home_device_list", map[string]interface{}{
		"home_owner":         c.us.UserID,
		"home_id":            homeID,
		"fetch_share_dev":    true,
		"limit":              200,
		"support_smart_home": true,
	}))
	if !ret.IsOK() {
		return nil, ret.Error
	}
	res := &homeDeviceListResponse{}
	if err := json.Unmarshal(ret.Result, res); err != nil {
		return nil, err
	}
	return res.Devices, nil
}

func (c *Client) GetDevices(ctx context.Context) ([]*DeviceInfo, error) {
	ret := c.Request(ctx, newRequest("/home/device_list", map[string]interface{}{
		"getVirtualModel":    true,
		"getHuamiDevices":    1,
		"get_split_device":   true,
		"support_smart_home": true,
	}))
	if !ret.IsOK() {
		return nil, ret.Error
	}
	res := &deviceListResponse{}
	if err := ret.Decode(res); err != nil {
		return nil, err
	}
	return res.List, nil
}

func (c *Client) GetLastMessage(ctx context.Context) ([]*SensorMessage, error) {
	ret := c.Request(ctx, newRequest("/v2/message/v2/typelist", map[string]interface{}{}))
	if !ret.IsOK() {
		return nil, ret.Error
	}
	res := &sensorMessageResponse{}
	if err := json.Unmarshal(ret.Result, res); err != nil {
		return nil, err
	}
	return res.Messages, nil
}

func (c *Client) GetSceneHistories(ctx context.Context, homeID int64) ([]*SceneHistory, error) {
	ret := c.Request(ctx, newRequest("/scene/history", map[string]interface{}{
		"home_id":   homeID,
		"uid":       c.us.UserID,
		"owner_uid": c.us.UserID,
		"command":   "history",
		"limit":     15,
	}))
	if !ret.IsOK() {
		return nil, ret.Error
	}
	res := &sceneHistoryResponse{}
	if err := ret.Decode(res); err != nil {
		return nil, err
	}
	return res.History, nil
}

func (c *Client) GetDeviceProperties(ctx context.Context, ps ...*types.DeviceProperty) error {
	ret := c.Request(ctx, newRequest("/miotspec/prop/get", map[string]interface{}{
		"params": ps,
	}))
	if !ret.IsOK() {
		return ret.Error
	}
	items := make([]*types.DeviceProperty, 0)
	if err := json.Unmarshal(ret.Result, &items); err != nil {
		return err
	}
	for _, row := range items {
		for _, p := range ps {
						if p.SIID == row.SIID && p.PIID == row.PIID {
				p.Value = row.Value
				p.Code = row.Code
				p.Modtime = row.Modtime
				break
			}
		}
	}
	return nil
}

func (c *Client) SetDeviceProperties(ctx context.Context, ps ...*types.DeviceProperty) error {
	ret := c.Request(ctx, newRequest("/miotspec/prop/set", map[string]interface{}{
		"params": ps,
	}))
	if !ret.IsOK() {
		return ret.Error
	}
	items := make([]*types.DeviceProperty, 0)
	if err := json.Unmarshal(ret.Result, &items); err != nil {
		return err
	}
	for _, row := range items {
		for _, p := range ps {
			if p.SIID == row.SIID && p.PIID == row.PIID {
				p.Value = row.Value
				p.Code = row.Code
				break
			}
		}
	}
	return nil
}

func (c *Client) ExecuteDeviceAction(ctx context.Context, args types.DeviceAction) error {
	ret := c.Request(ctx, newRequest("/miotspec/action", map[string]interface{}{
		"params": args,
	}))
	if !ret.IsOK() {
		return ret.Error
	}
	return nil
}

func (c *Client) Request(ctx context.Context, r *Request) *Response {
	var (
		err       error
		attempted bool
		res       *Response
	)
__retry:
	if res = c.doRequest(ctx, r); !res.IsOK() {
		if !attempted && res.Code == http.StatusUnauthorized {
			if err = c.login(ctx, true); err == nil {
				attempted = true
				goto __retry
			}
		}
	}
	return res
}

func (c *Client) CallRPC(ctx context.Context, did, method string, params interface{}) (*Response, error) {
	reqData := map[string]interface{}{
		"method": method,
		"params": params,
	}

	req := newRequest("/home/rpc/"+did, reqData)
	ret := c.Request(ctx, req)

	if !ret.IsOK() {
		return nil, ret.Error
	}
	return ret, nil
}

