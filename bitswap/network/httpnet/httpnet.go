package httpnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	bsmsg "github.com/ipfs/boxo/bitswap/message"
	pb "github.com/ipfs/boxo/bitswap/message/pb"
	"github.com/ipfs/boxo/bitswap/network"
	blocks "github.com/ipfs/go-block-format"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	probing "github.com/prometheus-community/pro-bing"
)

var log = logging.Logger("httpnet")

var ( // todo
	maxSendTimeout = 2 * time.Minute
	minSendTimeout = 10 * time.Second
	sendLatency    = 2 * time.Second
	minSendRate    = (100 * 1000) / 8 // 100kbit/s
)

var ErrNoHTTPAddresses = errors.New("AddrInfo does not contain any valid HTTP addresses")

var _ network.BitSwapNetwork = (*httpnet)(nil)

type Option func(net *httpnet)

func WithUserAgent(agent string) Option {
	return func(net *httpnet) {
		net.userAgent = agent
	}
}

type httpnet struct {
	// NOTE: Stats must be at the top of the heap allocation to ensure 64bit
	// alignment.
	stats network.Stats

	host   host.Host
	client *http.Client

	// inbound messages from the network are forwarded to the receiver
	receivers     []network.Receiver
	connectEvtMgr *network.ConnectEventManager

	urlLock   sync.RWMutex
	peerToURL map[peer.ID][]*url.URL
	urlToPeer map[string]peer.ID

	latMapLock sync.RWMutex
	latMap     map[peer.ID]time.Duration

	userAgent string
}

// New returns a BitSwapNetwork supported by underlying IPFS host.
func New(host host.Host, opts ...Option) network.BitSwapNetwork {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	c := &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext, // maybe breaks wasm
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	net := httpnet{
		host:      host,
		client:    c,
		peerToURL: make(map[peer.ID][]*url.URL),
		urlToPeer: make(map[string]peer.ID),
		latMap:    make(map[peer.ID]time.Duration),
	}

	for _, opt := range opts {
		opt(&net)
	}

	return &net
}

func (ht *httpnet) Start(receivers ...network.Receiver) {
	ht.receivers = receivers
	connectionListeners := make([]network.ConnectionListener, len(receivers))
	for i, v := range receivers {
		connectionListeners[i] = v
	}
	ht.connectEvtMgr = network.NewConnectEventManager(connectionListeners...)

	ht.connectEvtMgr.Start()
}

func (ht *httpnet) Stop() {
	ht.connectEvtMgr.Stop()
}

func (ht *httpnet) Ping(ctx context.Context, p peer.ID) ping.Result {
	log.Debugf("Ping: %s", p)

	pi := ht.host.Peerstore().PeerInfo(p)
	urls := network.ExtractURLsFromPeer(pi)
	if len(urls) == 0 {
		return ping.Result{
			Error: ErrNoHTTPAddresses,
		}
	}

	// pick the first one. In general there should not be more than one
	// url per peer. FIXME: right?
	pingURL := urls[0]

	pinger, err := probing.NewPinger(pingURL.Host)
	if err != nil {
		return ping.Result{
			RTT:   0,
			Error: err,
		}
	}
	pinger.Count = 1

	err = pinger.RunWithContext(ctx)
	if err != nil {
		return ping.Result{
			RTT:   0,
			Error: err,
		}
	}
	lat := pinger.Statistics().AvgRtt
	ht.recordLatency(p, lat)
	return ping.Result{
		RTT:   lat,
		Error: nil,
	}

}

// TODO
func (ht *httpnet) Latency(p peer.ID) time.Duration {
	var lat time.Duration
	ht.latMapLock.RLock()
	{
		lat = ht.latMap[p]
	}
	ht.latMapLock.RUnlock()

	// Add one more latency measurement every time latency is requested
	// since we don't do it from anywhere else.
	// FIXME: too much too often?
	go func() {
		ht.Ping(context.Background(), p)
	}()

	return lat
}

// similar to LatencyIWMA from peerstore.
func (ht *httpnet) recordLatency(p peer.ID, next time.Duration) {
	nextf := float64(next)
	s := 0.1
	ht.latMapLock.Lock()
	{
		ewma, found := ht.latMap[p]
		ewmaf := float64(ewma)
		if !found {
			ht.latMap[p] = next // when no data, just take it as the mean.
		} else {
			nextf = ((1.0 - s) * ewmaf) + (s * nextf)
			ht.latMap[p] = time.Duration(nextf)
		}
	}
	ht.latMapLock.Unlock()
}

func (ht *httpnet) SendMessage(ctx context.Context, p peer.ID, msg bsmsg.BitSwapMessage) error {
	log.Debugf("SendMessage: %s. %s", p, msg)
	// todo opts
	sender, err := ht.NewMessageSender(ctx, p, nil)
	if err != nil {
		return err
	}
	defer sender.Close()
	return sender.SendMsg(ctx, msg)
}

func (ht *httpnet) Self() peer.ID {
	return ht.host.ID()
}

func (ht *httpnet) Connect(ctx context.Context, p peer.AddrInfo) error {
	log.Debugf("Connect: %s", p)
	htaddrs, _ := network.SplitHTTPAddrs(p)
	if len(htaddrs.Addrs) == 0 {
		return nil
	}
	ht.host.Peerstore().AddAddrs(p.ID, htaddrs.Addrs, peerstore.PermanentAddrTTL)
	for _, r := range ht.receivers {
		r.PeerConnected(p.ID)
	}
	return nil
}

func (ht *httpnet) DisconnectFrom(ctx context.Context, p peer.ID) error {
	return nil
}

func (ht *httpnet) Stats() network.Stats {
	return network.Stats{
		MessagesRecvd: atomic.LoadUint64(&ht.stats.MessagesRecvd),
		MessagesSent:  atomic.LoadUint64(&ht.stats.MessagesSent),
	}
}

func (ht *httpnet) TagPeer(p peer.ID, tag string, w int) {
}
func (ht *httpnet) UntagPeer(p peer.ID, tag string) {
}

func (ht *httpnet) Protect(p peer.ID, tag string) {
}
func (ht *httpnet) Unprotect(p peer.ID, tag string) bool {
	return false
}

func (ht *httpnet) NewMessageSender(ctx context.Context, p peer.ID, opts *network.MessageSenderOpts) (network.MessageSender, error) {
	log.Debugf("NewMessageSender: %s", p)
	pi := ht.host.Peerstore().PeerInfo(p)
	urls := network.ExtractURLsFromPeer(pi)
	if len(urls) == 0 {
		return nil, ErrNoHTTPAddresses
	}

	return &httpMsgSender{
		// ctx ??
		peer:      p,
		urls:      urls,
		client:    ht.client,
		receivers: ht.receivers,
		closing:   make(chan struct{}, 1),
		// opts: todo
	}, nil
}

type httpMsgSender struct {
	client    *http.Client
	peer      peer.ID
	urls      []*url.URL
	receivers []network.Receiver
	opts      network.MessageSenderOpts
	closing   chan struct{}
	closeOnce sync.Once
}

func (sender *httpMsgSender) SendMsg(ctx context.Context, msg bsmsg.BitSwapMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bsresp := msg.Clone()

	go func() {
		for range sender.closing {
			cancel()
		}
	}()

	sendErrors := func(err error) {
		for _, recv := range sender.receivers {
			recv.ReceiveError(err)
		}
	}

	sendURL, _ := url.Parse(sender.urls[0].String())
	sendURL.RawQuery = "format=raw"

	// TODO: assuming we don't have to manage making concurrent
	// requests here.
	for _, entry := range msg.Wantlist() {
		var method string
		switch {
		case entry.Cancel:
			continue // todo: handle cancelling ongoing
		case entry.WantType == pb.Message_Wantlist_Block:
			method = "GET"
		case entry.WantType == pb.Message_Wantlist_Have:
			method = "HEAD"
		default:
			continue
		}

		sendURL.Path = "/ipfs/" + entry.Cid.String()
		headers := make(http.Header)
		headers.Add("Accept", "application/vnd.ipld.raw")

		req, err := http.NewRequestWithContext(ctx,
			method,
			sendURL.String(),
			nil,
		)
		if err != nil {
			log.Error(err)
			break
		}
		req.Header = headers
		log.Debugf("cid request to %s %s", method, sendURL)
		resp, err := sender.client.Do(req)
		if err != nil { // abort talking to this host
			log.Error(err)
			// send error?
			break
		}
		if resp.StatusCode == http.StatusNotFound {
			if entry.SendDontHave {
				bsresp.AddDontHave(entry.Cid)
			}
			continue
		}

		// TODO: fixme: limited reader
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error(err)
			break
		}

		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("%s -> %d: %s", sendURL, resp.StatusCode, string(body))
			sendErrors(err)
			log.Debug(err)
			continue
		}
		switch req.Method {
		case "GET":
			b, err := blocks.NewBlockWithCid(body, entry.Cid)
			if err != nil {
				log.Error("Block received for cid %s does not match!", entry.Cid)
				continue
			}
			bsresp.AddBlock(b)
			continue
		case "HEAD":
			bsresp.AddHave(entry.Cid)
			continue
		}
	}

	// send responses in background
	go func(receivers []network.Receiver, p peer.ID, msg bsmsg.BitSwapMessage) {
		// todo: do not hang if closing
		for i, recv := range receivers {
			log.Debugf("Calling ReceiveMessage from %s (receiver %d)", p, i)
			recv.ReceiveMessage(
				context.Background(), // todo: which context?
				p,
				msg,
			)
		}
	}(sender.receivers, sender.peer, bsresp)

	return nil
}

func (sender *httpMsgSender) Close() error {
	sender.closeOnce.Do(func() {
		close(sender.closing)
	})
	return nil
}

func (sender *httpMsgSender) Reset() error {
	return nil
}

func (sender *httpMsgSender) SupportsHave() bool {
	return false
}
